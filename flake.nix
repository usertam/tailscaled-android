{
  description = "Tailscale daemon Magisk module";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs = { self, nixpkgs }:
    let
      system = "aarch64-linux";
      pkgs = nixpkgs.legacyPackages.${system};

      tailscaled = pkgs.pkgsStatic.tailscale.overrideAttrs (prev: {
        name = "tailscaled-android";
        patches = (prev.patches or [ ]) ++ [
          ./patches/0001-linuxfw-relocate-fwmark-bits-for-netd.patch
          ./patches/0002-router-single-inverted-fwmark-ip-rule.patch
          ./patches/0003-paths-magisk-module-layout.patch
          ./patches/0004-osuser-hardcode-root-user.patch
          ./patches/0005-tailssh-default-path-from-init-environ.patch
          ./patches/0006-dns-noop-os-configurator-on-android.patch
        ];
        postInstall = "wrapProgram() { return; };" + prev.postInstall;
      });

      iptables = pkgs.pkgsStatic.iptables;
      rsync = pkgs.pkgsStatic.rsync.overrideAttrs (prev: { doCheck = false; });

      module = pkgs.stdenvNoCC.mkDerivation {
        pname = "tailscaled-magisk";
        version = tailscaled.version;
        src = ./module;
        nativeBuildInputs = [ pkgs.zip ];

        unpackPhase = ''
          cp -r $src source
          chmod +w source
          cd source
        '';

        configurePhase = ''
          substituteInPlace module.prop \
            --subst-var version
        '';

        buildPhase = ''
          install -Dm755 -t system/product/bin \
            ${tailscaled}/bin/tailscaled \
            ${iptables}/bin/xtables-legacy-multi \
            ${rsync}/bin/rsync
        '';

        installPhase = ''
          mkdir $out
          find . -type f -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
          find . -type f | LC_ALL=C sort | \
            TZ=UTC zip -X -q -@ $out/tailscaled-magisk-$version.zip
        '';
      };
    in
    {
      packages.${system} = {
        inherit tailscaled iptables rsync;
        default = module;
      };
    };
}
