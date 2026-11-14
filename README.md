# tailscaled-android

A Magisk module that runs `tailscaled` on Android, with Tailscale SSH and MagicDNS working out of the box. Everything is built declaratively and statically linked with Nix, so you can build it yourself:

```console
$ nix build .#packages.aarch64-linux.default
$ ls result/
tailscaled-magisk-1.104.5.zip
```

All the magic is in [patches/](patches/), [flake.nix](flake.nix) and [module/magicdns.sh](module/magicdns.sh).

Thank you to the blog [Full-Featured Tailscale on Android and Remote Unlocking](https://www.kxxt.dev/blog/full-tailscale-on-android-and-remote-unlocking/#patching-tailscale-for-android) for pointers on ip rules and netd fwmarks.

## Install

```console
(in adb shell or termux)
$ su
# tailscale up --ssh
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE)
file for details.
