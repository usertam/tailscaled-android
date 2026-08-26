{
  lib,
  stdenv,
  fetchzip,
  llvmPackages,
  linuxHeaders,
  libbpf,
}:

stdenv.mkDerivation {
  pname = "magicdns";
  version = "0-unstable-2026-08-27";

  src = lib.fileset.toSource {
    root = ./.;
    fileset = lib.fileset.unions [
      ./magicdns.bpf.c
      ./magicdns
    ];
  };

  nativeBuildInputs = [ llvmPackages.clang-unwrapped ];

  buildPhase = ''
    runHook preBuild

    clang -O2 -g -Wall -target bpf \
      -I${linuxHeaders}/include \
      -I${lib.getDev libbpf}/include \
      -c magicdns.bpf.c -o magicdns.bpf.o

    runHook postBuild
  '';

  installPhase =
    let
      bpftool = fetchzip {
        url = "https://github.com/libbpf/bpftool/releases/download/v7.7.0/bpftool-v7.7.0-arm64.tar.gz";
        hash = "sha256-/YtaeP+akpPyEyNlItaNkzulRM7dSIAgdRDZeiER3ac=";
        name = "bpftool-bin-7.7.0";
        postFetch = ''
          mkdir -p $out/bin
          mv $out/bpftool $out/bin/bpftool
          chmod +x $out/bin/bpftool
        '';
      };
    in
    ''
      runHook preInstall

      install -Dm444 -t $out/lib magicdns.bpf.o
      install -Dm755 -t $out/bin ${bpftool}/bin/bpftool ./magicdns

      runHook postInstall
    '';

  dontPatchShebangs = true;
}
