#!/system/bin/sh
MODDIR=${0%/*}

sh $MODDIR/magicdns.sh attach
exec $MODDIR/system/product/bin/tailscaled
