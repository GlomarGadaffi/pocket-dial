#ifndef L2_FRAME_FACTS_H
#define L2_FRAME_FACTS_H

// ── Ethernet / IPv4 frame facts (issue #1145) ─────────────────────────────────
//
// Reads what the L2 ingress verdict needs from one raw Ethernet frame, as the
// esp_eth input hook (main/pd_eth_ingress.c) receives it: no pbuf, no copy,
// nothing written to the frame. Pure, so the host suite pins every case.
//
// Only an untagged Ethernet II frame carrying a whole IPv4 header parses
// (return 1). VLAN-tagged (0x8100), ARP, IPv6, short and malformed frames
// return 0, and the caller defers them. A parsed frame carries its addresses
// even when it is not classified (ICMP, a non-first fragment): the gateway MAC
// pin learns from any frame of the gateway's IP. PD_L2F_IP4_UDP_TCP is set only
// for UDP or TCP whose ports are in the frame, and never on a non-first
// fragment. The IPv4 total length is not trusted: a MAC may pad, so every bound
// is against the frame length.

#include <stdint.h>

#include "L2IngressVerdict.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
	uint32_t srcIp, dstIp;      // host byte order
	uint32_t flags;             // PD_L2F_* facts of this frame
	uint16_t srcPort, dstPort;  // valid with PD_L2F_IP4_UDP_TCP
	const uint8_t *srcMac;      // 6 bytes inside the frame
} pd_l2_frame_facts_t;

PD_L2_INLINE uint32_t pd_l2_be16(const uint8_t *p)
{
	return ((uint32_t)p[0] << 8) | p[1];
}

PD_L2_INLINE uint32_t pd_l2_be32(const uint8_t *p)
{
	return (pd_l2_be16(p) << 16) | pd_l2_be16(p + 2);
}

PD_L2_INLINE int pd_l2_parse_frame(const uint8_t *buf, uint32_t len, pd_l2_frame_facts_t *out)
{
	enum { PD_ETH_HLEN = 14, PD_IP_MIN = 20 };
	out->flags = 0;
	out->srcIp = out->dstIp = 0;
	out->srcPort = out->dstPort = 0;
	out->srcMac = buf + 6;
	if (len < PD_ETH_HLEN + PD_IP_MIN || pd_l2_be16(buf + 12) != 0x0800) return 0;
	const uint8_t *ip = buf + PD_ETH_HLEN;
	const uint32_t ihl = (uint32_t)(ip[0] & 0x0F) * 4u;
	if ((ip[0] >> 4) != 4 || ihl < PD_IP_MIN || len < PD_ETH_HLEN + ihl) return 0;

	out->flags = PD_L2F_MAC_VISIBLE | ((buf[0] & 1u) ? PD_L2F_DST_BCAST_MCAST : 0u);
	out->srcIp = pd_l2_be32(ip + 12);
	out->dstIp = pd_l2_be32(ip + 16);
	if (pd_l2_be16(ip + 6) & 0x1FFFu)
	{
		out->flags |= PD_L2F_NON_FIRST_FRAGMENT;
		return 1;
	}
	if ((ip[9] == 6 || ip[9] == 17) && len >= PD_ETH_HLEN + ihl + 4u)
	{
		out->srcPort = (uint16_t)pd_l2_be16(ip + ihl);
		out->dstPort = (uint16_t)pd_l2_be16(ip + ihl + 2);
		out->flags |= PD_L2F_IP4_UDP_TCP;
	}
	return 1;
}

#ifdef __cplusplus
}
#endif

#endif // L2_FRAME_FACTS_H
