#!/system/bin/sh
MODDIR=${0%/*}

(
  resetprop -w sys.boot_completed 0
  until ip link show dev tailscale0 up >/dev/null 2>&1; do
    sleep 10
  done
  $MODDIR/ebpf/magicdns attach tailscale0 $(cd /sys/class/net; ls -d rmnet_data* wlan*)
) &

exec env XTABLES_LOCKFILE=/data/adb/tailscale/xtables.lock \
  $MODDIR/system/product/bin/tailscaled
