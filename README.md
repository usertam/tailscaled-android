# tailscaled-android

A Magisk module that runs the upstream `tailscaled` daemon natively on
rooted Android, with a small patch set that makes Tailscale coexist with
Android's `netd` policy routing.

The build is reproducible: Nix flake → static `tailscaled` + static
`iptables` → Magisk zip. No NDK, no Android Studio, no `go build` on the
host.

## What's in the module

- `tailscaled` (and a `tailscale` symlink) installed under
  `/system/product/bin`, statically linked against musl.
- `xtables-legacy-multi` with `iptables` / `ip6tables` symlinks, so
  `tailscaled` can program the firewall without depending on whatever
  the vendor ROM ships.
- `service.sh` execs `tailscaled` at late boot. State and the control
  socket live under `/data/adb/tailscale/` (persistent across OTA).
- `uninstall.sh` kills the daemon and wipes `/data/adb/tailscale`.

## The patch

[tailscaled-android.patch](tailscaled-android.patch) carries two
behavioural changes against upstream Tailscale:

1. **State / socket paths** ([paths/paths.go](tailscaled-android.patch),
   [paths/paths_unix.go](tailscaled-android.patch)) — point at
   `/data/adb/tailscale/` instead of `/var/lib/tailscale` and
   `/var/run/tailscale`, neither of which is persistent or even present
   on Android.

2. **Firewall mark bits** ([tsconst/linuxfw.go](tailscaled-android.patch)
   and [wgengine/router/osrouter/router_linux.go](tailscaled-android.patch))
   — move from bits 16:23 (`0xff0000`) to bits 25:28 (`0x1e000000`), and
   collapse the historical pref 10/30/50 bypass-mark trio into a single
   inverted-fwmark rule at pref 70.

   Upstream's bit layout collides with `netd`'s netId / permission /
   billing flags, and the bypass-mark rule trio fires before `netd`'s
   per-network/per-uid policy at pref >=10000, short-circuiting it.
   The new layout sits in `netd`'s reserved-upper-half byte, and the
   single inverted rule lets bypass-marked packets fall through to
   `netd` instead of stealing them.

Thank you to the blog
[Full-Featured Tailscale on Android and Remote Unlocking](https://www.kxxt.dev/blog/full-tailscale-on-android-and-remote-unlocking/#patching-tailscale-for-android).

## Building

Requires Nix with flakes enabled. `aarch64-linux` is the only target —
build on an ARM Linux host, or use `boot.binfmt.emulatedSystems` /
remote builders from x86_64.

```console
$ nix build
$ ls result/
tailscaled-magisk-1.98.0.zip
```

The default package is the Magisk zip; the bare `tailscaled` binary is
also exposed:

```console
$ nix build .#tailscaled
$ ls result/bin/
get-authkey  tailscale  tailscaled
```

## Installing

Flash `result/tailscaled-magisk-*.zip` in the Magisk app and reboot.
Then, in `adb shell` as root:

```console
# tailscale up --ssh
```

State persists at `/data/adb/tailscale/`. Uninstall to wipe it.


## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE)
file for details.
