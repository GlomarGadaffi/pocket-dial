#ifndef L2_INGRESS_VERDICT_H
#define L2_INGRESS_VERDICT_H

// ── L2 ingress verdict (issue #1145) ──────────────────────────────────────────
//
// Classifies one inbound frame for COUNTING: nothing here drops anything, a
// WOULD_DROP class is a counter bucket. The caller gathers the facts (addresses,
// MAC and allowlist lookups) and this decides from them, so the host suite can
// pin every branch.
//
// The rule order is the safety property; the first rule that matches wins:
//   1. Unknown state DEFERs: our IP, mask or gateway not yet known (0), a frame
//      that is not IPv4 UDP/TCP (the caller flags ARP, ICMP, IPv6 and
//      VLAN-tagged frames that way), or a non-first fragment.
//   2. An emergency IP in either direction, or an open callback window: PASS,
//      ahead of every later rule.
//   3. A trunk peer: PASS.
//   4. A broadcast or multicast destination DEFERs (DHCP DISCOVER
//      0.0.0.0 -> 255.255.255.255, mDNS), whether the caller flagged it or
//      dstIp shows it (224/3 and up, or a subnet-directed broadcast).
//   5. A source in 0/8, 127/8 or 240/4 to our own unicast: WOULD_DROP_MARTIAN.
//      To any other unicast it falls through to rules 6-7.
//      lwIP already drops broadcast and multicast sources.
//   6. An on-link source PASSes, except one that arrives with the gateway's
//      MAC while not being the gateway's IP: WOULD_DROP_LAN_GW_MAC. The gateway
//      does not send LAN-sourced traffic back onto the LAN. That class needs a
//      visible source MAC and a pinned, unchanged gateway MAC; a MAC fact we
//      cannot establish never yields a WOULD_DROP.
//   7. An off-link source to any address but ours DEFERs: a frame not
//      addressed to us is not one of our services. Otherwise it PASSes if it
//      is in the ACL or on a flow the board opened; to a port off the service
//      list it DEFERs (ephemeral media ports,
//      911 and callback media included, are never classified); to a listed
//      service port it is WOULD_DROP_WAN_SERVICE.
//   8. Anything else DEFERs.

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum
{
	PD_L2_PASS = 0,
	PD_L2_DEFER = 1,
	PD_L2_WOULD_DROP_MARTIAN = 2,
	PD_L2_WOULD_DROP_LAN_GW_MAC = 3,
	PD_L2_WOULD_DROP_WAN_SERVICE = 4,
};

// pd_l2_frame_t.flags: facts the caller established for this frame.
enum
{
	PD_L2F_IP4_UDP_TCP = 1u << 0,         // IPv4 carrying UDP or TCP
	PD_L2F_NON_FIRST_FRAGMENT = 1u << 1,  // fragment offset != 0
	PD_L2F_DST_BCAST_MCAST = 1u << 2,     // destination broadcast or multicast;
	                                      // also derived from dstIp and mask
	PD_L2F_MAC_VISIBLE = 1u << 3,         // source MAC known to the caller
	PD_L2F_GW_MAC_PINNED = 1u << 4,       // a gateway MAC has been learned
	PD_L2F_GW_MAC_CHANGED = 1u << 5,      // ...and has since changed
	PD_L2F_SRC_MAC_IS_GW = 1u << 6,       // source MAC == pinned gateway MAC
	PD_L2F_EMERGENCY = 1u << 7,           // an emergency IP, either direction
	PD_L2F_CALLBACK_WINDOW = 1u << 8,     // an emergency callback window is open
	PD_L2F_TRUNK_PEER = 1u << 9,          // source is a trunk peer
	PD_L2F_SRC_IN_ACL = 1u << 10,         // source is in the ACL
	PD_L2F_SERVICE_PORT = 1u << 11,       // destination port is on the service list
	PD_L2F_OWN_FLOW = 1u << 12,           // part of a flow the board opened
};

// Addresses in HOST byte order; ourIp / mask / gateway 0 = not known yet.
typedef struct
{
	uint32_t ourIp, mask, gateway;
	uint32_t srcIp, dstIp;
	uint32_t flags;
} pd_l2_frame_t;

static inline int pd_l2_is_martian_src(uint32_t src)
{
	const uint32_t top = src >> 24;
	return top == 0 || top == 127 || top >= 240;
}

// Flagged by the caller, or multicast / 255.255.255.255 (224/3 and up), or the
// subnet-directed broadcast of any subnet under our mask. Needs mask != 0.
static inline int pd_l2_dst_is_bcast_mcast(const pd_l2_frame_t *f)
{
	if (f->flags & PD_L2F_DST_BCAST_MCAST) return 1;
	if (f->dstIp >= 0xE0000000u) return 1;
	return f->mask != 0xFFFFFFFFu && (f->dstIp & ~f->mask) == ~f->mask;
}

static inline int pd_l2_on_link_verdict(const pd_l2_frame_t *f)
{
	const uint32_t need = PD_L2F_MAC_VISIBLE | PD_L2F_GW_MAC_PINNED | PD_L2F_SRC_MAC_IS_GW;
	if (f->srcIp == f->gateway) return PD_L2_PASS;
	if ((f->flags & need) != need || (f->flags & PD_L2F_GW_MAC_CHANGED)) return PD_L2_PASS;
	return PD_L2_WOULD_DROP_LAN_GW_MAC;
}

static inline int pd_l2_off_link_verdict(const pd_l2_frame_t *f)
{
	const uint32_t flags = f->flags;
	if (f->dstIp != f->ourIp) return PD_L2_DEFER;
	if (flags & (PD_L2F_SRC_IN_ACL | PD_L2F_OWN_FLOW)) return PD_L2_PASS;
	if (!(flags & PD_L2F_SERVICE_PORT)) return PD_L2_DEFER;
	return PD_L2_WOULD_DROP_WAN_SERVICE;
}

static inline int pd_l2_ingress_verdict(const pd_l2_frame_t *f)
{
	const uint32_t fl = f->flags;
	if (!f->ourIp || !f->mask || !f->gateway) return PD_L2_DEFER;
	if (!(fl & PD_L2F_IP4_UDP_TCP)) return PD_L2_DEFER;
	if (fl & PD_L2F_NON_FIRST_FRAGMENT) return PD_L2_DEFER;
	if (fl & PD_L2F_EMERGENCY) return PD_L2_PASS;
	if (fl & PD_L2F_CALLBACK_WINDOW) return PD_L2_PASS;
	if (fl & PD_L2F_TRUNK_PEER) return PD_L2_PASS;
	if (pd_l2_dst_is_bcast_mcast(f)) return PD_L2_DEFER;
	if (pd_l2_is_martian_src(f->srcIp) && f->dstIp == f->ourIp) return PD_L2_WOULD_DROP_MARTIAN;
	if ((f->srcIp & f->mask) == (f->ourIp & f->mask)) return pd_l2_on_link_verdict(f);
	return pd_l2_off_link_verdict(f);
}

#ifdef __cplusplus
}
#endif

#endif // L2_INGRESS_VERDICT_H
