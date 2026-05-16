{
  description = "Tailscale daemon Magisk module";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs = { self, nixpkgs }:
    let
      system = "aarch64-linux";
      pkgs = nixpkgs.legacyPackages.${system};

      tailscaled = pkgs.pkgsStatic.tailscale.overrideAttrs (prev: {
        name = "tailscaled-android";
        patches = (prev.patches or [ ]) ++ [ ./tailscaled-android.patch ];
        postInstall = "wrapProgram() { return; };" + prev.postInstall;
      });

      iptables = pkgs.pkgsStatic.iptables;
      rsync = pkgs.pkgsStatic.rsync.overrideAttrs (prev: { doCheck = false; });

      module = pkgs.runCommand "tailscaled-magisk" {
        src = ./module;
        nativeBuildInputs = [ pkgs.zip ];
      } ''
        cp -r $src source
        chmod +w source
        cd source
        install -Dm755 -t system/product/bin \
          ${tailscaled}/bin/tailscaled \
          ${iptables}/bin/xtables-legacy-multi \
          ${rsync}/bin/rsync

        mkdir $out
        find . -type f -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
        find . -type f | LC_ALL=C sort | \
          TZ=UTC zip -X -q -@ $out/tailscaled-magisk-${tailscaled.version}.zip
      '';
    in
    {
      packages.${system} = {
        inherit tailscaled iptables rsync;
        default = module;
      };
    };
}
