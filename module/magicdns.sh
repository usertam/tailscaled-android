#!/system/bin/sh
# magicdns.sh — divert single-label DNS queries to MagicDNS via iptables.
#
#   magicdns.sh attach    install the nat rules
#   magicdns.sh detach    remove them
#
# One nat OUTPUT rule: UDP/53 queries whose question is a single label
# are DNATed to 100.100.100.100, the policy route for quad-100 (table
# 52, behind tailscaled's pref 70 rule) carries them into the tun, and
# conntrack restores the reply's source, so a client whose socket is
# connect()ed to its resolver still gets an answer from that resolver.
# Nothing is per-device: uplinks that appear after attach are covered
# too. tailscaled's own queries carry its bypass mark and are left
# alone, so a forwarded single-label query cannot loop back.
#
# The nat table is consulted only for the first packet of a conntrack
# flow; later packets on the same 5-tuple follow its verdict, whatever
# name they ask for.

set -eu

MODDIR=${0%/*}
PATH=$PATH:$MODDIR/system/product/bin
Q=100.100.100.100
BYPASS=0x10000000/0x1e000000	# tsconst.LinuxBypassMark, patch 0001

# The single-label test, as classic BPF for xt_bpf, which Android's
# netd already requires. It travels inside the rule, so there is no
# object to build or pin: a pinned eBPF program would be referenced by
# path, and the kernel re-opens that path whenever any process (netd,
# say) replaces the nat table.
#
# A wire-format name is length-prefixed labels ending in a zero byte:
# "printer" is {7,'p',...,'r',0}, "printer.lan" {7,...,3,'l','a','n',0}.
# Exactly one label iff the first length n is 1..63 and the byte after
# those n bytes is the terminator; n == 0 is the root name, n > 63 a
# compression pointer. The packet starts at the IPv4 header, and the
# OUTPUT rule has already matched UDP, port 53, first fragment.
#   0  ldxb 4*([0]&0xf)    X = IHL*4, the UDP header
#   1  ldb  [x+10]         DNS flags, high byte
#   2  jset #0xf8, 13      QR or opcode set: not a plain query
#   3  ldh  [x+12]         QDCOUNT
#   4  jeq  #1, 5, 13
#   5  ldb  [x+20]         first label length n
#   6  jeq  #0, 13
#   7  jgt  #63, 13
#   8  add  x
#   9  tax                 X = IHL*4 + n
#  10  ldb  [x+21]         byte after the label
#  11  jeq  #0, 12, 13
#  12  ret  #1             match
#  13  ret  #0
# A load past the end of the packet returns 0, i.e. no match.
SINGLE_LABEL='14,177 0 0 0,80 0 0 10,69 10 0 248,72 0 0 12,21 0 8 1,80 0 0 20,21 6 0 0,37 5 0 63,12 0 0 0,7 0 0 0,80 0 0 21,21 0 1 0,6 0 0 1,6 0 0 0'

usage() {
	echo "usage: magicdns.sh attach|detach" >&2
	exit 2
}

[ $# -eq 1 ] || usage

case $1 in
attach)
	iptables -w -t nat -N magicdns 2>/dev/null || iptables -w -t nat -F magicdns
	iptables -w -t nat -A magicdns -m mark --mark $BYPASS -j RETURN
	iptables -w -t nat -A magicdns -d $Q -j RETURN
	iptables -w -t nat -A magicdns -m bpf --bytecode "$SINGLE_LABEL" \
		-j DNAT --to-destination $Q
	iptables -w -t nat -C OUTPUT -p udp --dport 53 -j magicdns 2>/dev/null ||
		iptables -w -t nat -I OUTPUT -p udp --dport 53 -j magicdns
	;;
detach)
	iptables -w -t nat -D OUTPUT -p udp --dport 53 -j magicdns 2>/dev/null || true
	iptables -w -t nat -F magicdns 2>/dev/null || true
	iptables -w -t nat -X magicdns 2>/dev/null || true
	;;
*)
	usage
	;;
esac
