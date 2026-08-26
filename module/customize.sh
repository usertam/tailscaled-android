SKIPUNZIP=0

set_perm $MODPATH/system/product/bin/tailscaled 0 0 0755
ln -sf tailscaled $MODPATH/system/product/bin/tailscale

set_perm $MODPATH/system/product/bin/xtables-legacy-multi 0 0 0755
ln -sf xtables-legacy-multi $MODPATH/system/product/bin/iptables
ln -sf xtables-legacy-multi $MODPATH/system/product/bin/ip6tables

set_perm $MODPATH/system/product/bin/rsync 0 0 0755

set_perm $MODPATH/ebpf/magicdns 0 0 0755
set_perm $MODPATH/ebpf/bpftool 0 0 0755

mkdir -p /data/adb/tailscale
set_perm /data/adb/tailscale 0 0 0700
