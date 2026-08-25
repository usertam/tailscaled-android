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

## The patches

[patches/](patches/) carries the behavioural changes against upstream
Tailscale. Runtime Android detection keys off the existence of
`/data/adb/tailscale`, which the module creates on install; elsewhere
the binary behaves like upstream.

1. **Firewall mark bits**
   ([0001](patches/0001-linuxfw-relocate-fwmark-bits-for-netd.patch),
   [0002](patches/0002-router-single-inverted-fwmark-ip-rule.patch))
   — move from bits 16:23 (`0xff0000`) to bits 25:28 (`0x1e000000`), and
   collapse the historical pref 10/30/50 bypass-mark trio into a single
   inverted-fwmark rule at pref 70.

   Upstream's bit layout collides with `netd`'s netId / permission /
   billing flags, and the bypass-mark rule trio fires before `netd`'s
   per-network/per-uid policy at pref >=10000, short-circuiting it.
   The new layout sits in `netd`'s reserved-upper-half byte, and the
   single inverted rule lets bypass-marked packets fall through to
   `netd` instead of stealing them.

2. **State / socket paths**
   ([0003](patches/0003-paths-magisk-module-layout.patch)) — prefer
   `/data/adb/tailscale/` over `/var/lib/tailscale` and
   `/var/run/tailscale`, neither of which is persistent or even present
   on Android.

3. **Tailscale SSH usability**
   ([0004](patches/0004-osuser-hardcode-root-user.patch),
   [0005](patches/0005-tailssh-default-path-from-init-environ.patch)) —
   hand back a hardcoded root user instead of shelling out to
   getent/NSS (which Android doesn't ship), and derive the default
   PATH from init's environment instead of glibc-distro guesses.

4. **MagicDNS**
   ([0006](patches/0006-dns-noop-os-configurator-on-android.patch)) —
   Android has no `/etc/resolv.conf`, so upstream's Linux probe falls
   back to the "direct" resolv.conf manager, whose failure on the
   missing file aborts DNS reconfiguration before the built-in quad-100
   resolver (`100.100.100.100`) is even configured. Use the noop
   configurator instead, like the official `GOOS=android` build:
   quad-100 still serves MagicDNS and forwards to the tailnet's
   resolvers. Redirecting the system's DNS traffic to quad-100 is
   handled out-of-band (an eBPF program), not by tailscaled.

Thank you to the blog
[Full-Featured Tailscale on Android and Remote Unlocking](https://www.kxxt.dev/blog/full-tailscale-on-android-and-remote-unlocking/#patching-tailscale-for-android).

## Building

Requires Nix with flakes enabled. `aarch64-linux` is the only target —
build on an ARM Linux host, or use `boot.binfmt.emulatedSystems` /
remote builders from x86_64.

```console
$ nix build
$ ls result/
tailscaled-magisk-1.102.2.zip
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
