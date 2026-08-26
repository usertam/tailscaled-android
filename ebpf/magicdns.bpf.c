// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * magicdns.bpf.c — transparently divert single-label DNS queries to a
 * MagicDNS resolver living behind a tun device.
 *
 * The problem: applications resolve bare names like "printer" through
 * whatever resolver R is in /etc/resolv.conf, which answers NXDOMAIN.
 * A local daemon (e.g. tailscaled) can answer these names, but it only
 * listens on 100.100.100.100:53 ("Q"), an address routed through its
 * own tun device — and we cannot rewrite resolv.conf.
 *
 * The trick, in two tc (clsact) programs sharing one map:
 *
 *   dns_out — attached to the EGRESS of each physical/uplink device.
 *   Spots IPv4/UDP packets to port 53 that are DNS queries for exactly
 *   one label, remembers "client (src IP, src port, DNS txn ID) was
 *   really asking R", rewrites the destination address R -> Q, and
 *   redirects the packet into the tun device. The daemon behind the
 *   tun sees a normal query addressed to Q and answers it.
 *
 *   dns_in — attached to the INGRESS of the tun device. Spots the
 *   daemon's replies (source Q, source port 53), looks the client back
 *   up in the map, and rewrites the source address Q -> R before the
 *   stack delivers it. This matters because the client's UDP socket is
 *   usually connect()ed to R (glibc's resolver does this), so a reply
 *   "from Q" would be filtered by the kernel's 4-tuple match; after
 *   the rewrite the client sees a well-formed answer from the resolver
 *   it actually queried.
 *
 * Everything that is not such a query/reply — other protocols, multi-
 * label names, fragments, packets we fail to parse — passes through
 * untouched. Every error path declines rather than drops: worst case
 * the query reaches the real resolver and gets its NXDOMAIN, never a
 * mangled packet or a black hole.
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>
#include <linux/stddef.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual MIT/GPL";

#define MAGICDNS_Q	bpf_htonl(0x64646464)	/* 100.100.100.100 */
#define DNS_PORT	bpf_htons(53)

/*
 * Load-time configuration. Lives in .rodata and is written by the
 * loader before the object is loaded, so the verifier sees constants
 * and folds them into the code — no per-packet map lookup, and with
 * tun_ifindex == 0 dns_out is dead-code-eliminated down to "return".
 *
 * l2_off is where the IPv4 header starts within the packet as tc sees
 * it, which depends on the attachment device's link-layer type: 14 on
 * Ethernet (the frame starts with an Ethernet header), 0 on devices
 * that carry raw IP (tun, rawip). The loader derives it from the
 * device type (SIOCGIFHWADDR) and refuses unknown types; it is never
 * operator-settable, because a wrong value here means parsing garbage
 * as IP. One object instance is loaded per attachment, so each gets
 * its own value. dns_in never needs it: a tun device is always raw
 * IP, offset 0.
 */
volatile const struct {
	__u32 tun_ifindex;	/* 0 disables dns_out */
	__u32 l2_off;		/* 14 for ARPHRD_ETHER, 0 for RAWIP/NONE */
} cfg = {};

/*
 * Query state, written by dns_out and read by dns_in — all loaded
 * instances share this one map. Key: who asked, precisely enough to
 * match the reply — client source address S, source port P, DNS
 * transaction ID T, stored as raw wire bytes (hence the hole-free
 * assert: the key is compared as memory). Value: the resolver address
 * R the client originally addressed, i.e. what to put back as the
 * reply's source.
 *
 * Entries are never deleted, only LRU-evicted. Deleting on first
 * reply would break duplicated answers (retransmits, dual replies),
 * which must all be translated; stale entries simply age out.
 */
struct dns_key {
	__be32 s;		/* source address of the query */
	__be16 p;		/* source port of the query */
	__be16 t;		/* DNS transaction ID */
};
_Static_assert(sizeof(struct dns_key) == 8, "key must be hole-free");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1024);
	__type(key, struct dns_key);
	__type(value, __be32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} dns_state SEC(".maps");

/*
 * Shared L3/L4 parse. Everything is copied into stack locals up
 * front, for two reasons: the checksum/store helpers used later may
 * reallocate skb data and invalidate anything read from the packet,
 * so all reads must precede the first write; and bpf_skb_load_bytes
 * fails cleanly on short packets, which maps directly onto our "can't
 * parse it — then it isn't ours" policy.
 *
 * Returns 0 with iph/uh/dns and the header offsets filled in, nonzero
 * if the packet is not IPv4, not UDP, a non-first fragment (offset
 * != 0 — L4 headers only exist in the first fragment), or too short.
 * The UDP header is located at ip_off + IHL*4, honouring IP options
 * rather than assuming a 20-byte header.
 */
struct hdrs {
	struct iphdr iph;	/* first 20 bytes; options not needed */
	struct udphdr uh;
	__u8 dns[12];		/* DNS fixed header */
	__u32 ip_off;		/* offset of the IPv4 header */
	__u32 udp_off;
	__u32 dns_off;
};

static __always_inline int parse(struct __sk_buff *skb, __u32 l2_off,
				 struct hdrs *h)
{
	h->ip_off = l2_off;

	if (bpf_skb_load_bytes(skb, h->ip_off, &h->iph, sizeof(h->iph)))
		return -1;
	if (h->iph.version != 4 || h->iph.ihl < 5)
		return -1;
	if (h->iph.protocol != IPPROTO_UDP)
		return -1;
	/* fragment offset != 0: no UDP/DNS header in this packet */
	if (h->iph.frag_off & bpf_htons(0x1fff))
		return -1;

	/* skip IP options if present */
	h->udp_off = h->ip_off + (__u32)h->iph.ihl * 4;
	if (bpf_skb_load_bytes(skb, h->udp_off, &h->uh, sizeof(h->uh)))
		return -1;

	h->dns_off = h->udp_off + 8;
	if (bpf_skb_load_bytes(skb, h->dns_off, h->dns, sizeof(h->dns)))
		return -1;

	return 0;
}

/*
 * DNS fixed header, byte view: dns[0..1] transaction ID; dns[2] bit 7
 * is QR (0 query, 1 response), bits 6..3 the opcode (0 = standard
 * query); dns[4..5] QDCOUNT, the question count, big-endian.
 */
#define DNS_QR(h)	((h)->dns[2] & 0x80)
#define DNS_OPCODE(h)	((h)->dns[2] & 0x78)	/* nonzero ⇔ not QUERY */
#define DNS_QDCOUNT1(h)	((h)->dns[4] == 0 && (h)->dns[5] == 1)

/*
 * Rewrite one IPv4 address at ip_off+addr_off from `from` to `to`,
 * keeping both checksums correct: incrementally patch the IP header
 * checksum, incrementally patch the UDP checksum (the flags say the
 * changed bytes belong to the pseudo-header, that UDP's "checksum 0 =
 * no checksum" convention applies — a zero checksum stays zero and a
 * recomputed zero is written as 0xffff — and that 4 bytes changed),
 * then store the address itself.
 *
 * Incremental update rather than recompute is deliberate: on egress
 * the skb may carry an offloaded partial checksum, where the field's
 * current value is not the final sum; folding a delta is correct in
 * both the offloaded and the fully-computed case. With old/new passed
 * explicitly, the order of the three calls doesn't matter.
 */
static __always_inline int rewrite_addr(struct __sk_buff *skb,
					const struct hdrs *h,
					__u32 addr_off,
					__be32 from, __be32 to)
{
	if (bpf_l3_csum_replace(skb, h->ip_off + offsetof(struct iphdr, check),
				from, to, 4))
		return -1;
	if (bpf_l4_csum_replace(skb, h->udp_off + offsetof(struct udphdr, check),
				from, to,
				BPF_F_PSEUDO_HDR | BPF_F_MARK_MANGLED_0 | 4))
		return -1;
	if (bpf_skb_store_bytes(skb, h->ip_off + addr_off, &to, 4, 0))
		return -1;
	return 0;
}

/* Egress of each uplink device: divert single-label queries into the tun. */
SEC("tc")
int dns_out(struct __sk_buff *skb)
{
	struct hdrs h;
	struct dns_key k = {};	/* zeroed: compared as raw memory */
	__be32 r, q = MAGICDNS_Q;
	__u8 n, term;

	/* unconfigured: do nothing (verifier folds this to a constant) */
	if (!cfg.tun_ifindex)
		return TC_ACT_OK;
	/* harmless if attached to the tun itself: never redirect a
	 * packet back into the device it is already leaving through */
	if (skb->ifindex == cfg.tun_ifindex)
		return TC_ACT_OK;
	if (skb->protocol != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;

	/* IPv4 + UDP + first fragment + long enough, into locals */
	if (parse(skb, cfg.l2_off, &h))
		return TC_ACT_OK;
	if (h.uh.dest != DNS_PORT)
		return TC_ACT_OK;
	/* already addressed to Q: nothing to divert. Also guarantees
	 * we never store R == Q, so replies always translate back to
	 * something other than Q. */
	if (h.iph.daddr == MAGICDNS_Q)
		return TC_ACT_OK;
	/* a plain question: QR=query, opcode=QUERY, exactly 1 question */
	if (DNS_QR(&h) || DNS_OPCODE(&h) || !DNS_QDCOUNT1(&h))
		return TC_ACT_OK;

	/*
	 * The single-label test. A DNS name on the wire is a sequence
	 * of length-prefixed labels ending in a zero byte, so "printer"
	 * is {7,'p','r','i','n','t','e','r',0} while "example.com" is
	 * {7,...,3,'c','o','m',0}. Exactly one label iff the first
	 * length byte n is 1..63 and the byte right after those n
	 * label bytes is the terminating 0. n == 0 is the root name;
	 * n > 63 has the top bits set, i.e. a compression pointer,
	 * which cannot start a sane query name — both pass through.
	 * So does any name whose bytes run past the end of the packet.
	 */
	if (bpf_skb_load_bytes(skb, h.dns_off + 12, &n, 1))
		return TC_ACT_OK;
	if (n == 0 || n > 63)
		return TC_ACT_OK;
	if (bpf_skb_load_bytes(skb, h.dns_off + 12 + 1 + n, &term, 1))
		return TC_ACT_OK;
	if (term != 0x00)
		return TC_ACT_OK;

	/*
	 * Remember who asked and whom they asked — fields exactly as
	 * they appear on the wire — BEFORE touching the packet: if the
	 * map update fails we decline with the packet still intact and
	 * it simply travels on to the real resolver. Then rewrite the
	 * destination to Q. The source is left alone.
	 */
	k.s = h.iph.saddr;
	k.p = h.uh.source;
	__builtin_memcpy(&k.t, &h.dns[0], 2);
	r = h.iph.daddr;
	if (bpf_map_update_elem(&dns_state, &k, &r, BPF_ANY))
		return TC_ACT_OK;

	if (rewrite_addr(skb, &h, offsetof(struct iphdr, daddr),
			 h.iph.daddr, q))
		return TC_ACT_OK;

	/*
	 * Hand the packet to the tun's transmit path. The Ethernet
	 * header (if any) is deliberately left in place: for devices
	 * without link-layer headers the kernel's redirect path strips
	 * the mac header itself before injecting.
	 */
	return bpf_redirect(cfg.tun_ifindex, 0);
}

/* Ingress of the tun: give the daemon's replies back their expected source. */
SEC("tc")
int dns_in(struct __sk_buff *skb)
{
	struct hdrs h;
	struct dns_key k = {};
	__be32 *rp, r;

	if (skb->protocol != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;
	/* tun frames start at the IP header: offset 0, unconditionally */
	if (parse(skb, 0, &h))
		return TC_ACT_OK;
	/* only the MagicDNS resolver's own replies are of interest */
	if (h.iph.saddr != MAGICDNS_Q)
		return TC_ACT_OK;
	if (h.uh.source != DNS_PORT)
		return TC_ACT_OK;
	/* a reply with exactly one question, mirroring the query */
	if (!DNS_QR(&h) || !DNS_QDCOUNT1(&h))
		return TC_ACT_OK;

	/*
	 * The reply is the query reversed: the client's address S is
	 * now the destination, its port P the destination port, and
	 * the transaction ID T is echoed. Unknown key — not a query we
	 * diverted — passes through untouched. The entry is looked up,
	 * never deleted: duplicate answers must translate too.
	 */
	k.s = h.iph.daddr;
	k.p = h.uh.dest;
	__builtin_memcpy(&k.t, &h.dns[0], 2);
	rp = bpf_map_lookup_elem(&dns_state, &k);
	if (!rp)
		return TC_ACT_OK;
	r = *rp;

	/* restore the source to R; the destination is already the client */
	rewrite_addr(skb, &h, offsetof(struct iphdr, saddr),
		     h.iph.saddr, r);
	return TC_ACT_OK;
}
