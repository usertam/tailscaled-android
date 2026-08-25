#!/system/bin/sh
MODDIR=${0%/*}
exec env XTABLES_LOCKFILE=/data/adb/tailscale/xtables.lock \
  $MODDIR/system/product/bin/tailscaled
