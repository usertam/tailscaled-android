#!/system/bin/sh
MODDIR=${0%/*}
exec $MODDIR/system/product/bin/tailscaled
