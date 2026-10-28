#ifndef L2_INGRESS_PARSE_H
#define L2_INGRESS_PARSE_H

// ── L2 ingress parse (issue #1145) ────────────────────────────────────────────
//
// Turns the raw bytes the IPv4 input hook sees (main/pd_lwip_hooks.c) into a
// pd_l2_frame_t and classifies it with pd_l2_ingress_verdict(). COUNT ONLY:
// the hook bumps a counter per would-drop class and lets every frame through.
//
// The hook runs before lwIP checks the header checksum, length or IHL, so
// this trusts nothing: it reads only inside the bytes it is given (the first
// pbuf), and anything it cannot read DEFERs.
//
// Facts this parse cannot know stay clear: no source MAC (the IPv4 hook has
// none), and no emergency, callback, trunk-peer, allowlist or own-flow facts.
// So an off-link SIP peer such as a carrier's SBC counts as wanService here.
// These counters come before those facts exist and are never used to drop.
//
// Pure and dependency-free so the host suite pins it (L2IngressParse_test).

#include <stdint.h>

#include "L2IngressVerdict.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PD_L2_PROTO_TCP 6u
#define PD_L2_PROTO_UDP 17u
#define PD_L2_IP4_MIN_HLEN 20u

// The service list: SIP on 5060 (UDP and TCP) and the dashboard
// (HTTP_DASHBOARD_PORT in main/esp_main*.cpp, 80 on every ESP build).
static inline int pd_l2_is_service_port(uint8_t proto, uint16_t port)
{
	static const struct { uint8_t proto; uint16_t port; } kList[] = {
		{ PD_L2_PROTO_UDP, 5060 }, { PD_L2_PROTO_TCP, 5060 }, { PD_L2_PROTO_TCP, 80 },
	};
	for (unsigned i = 0; i < sizeof kList / sizeof kList[0]; ++i)
		if (kList[i].proto == proto && kList[i].port == port) return 1;
	return 0;
}

static inline uint32_t pd_l2_be32(const uint8_t *b)
{
	return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | b[3];
}

// b: the IPv4 header onward; len: bytes readable at b. The UDP/TCP destination
// port in host order, or -1: short input, IHL under 5 words, a non-first
// fragment, not UDP/TCP, or the port beyond len. IHL options shift the read.
static inline int32_t pd_l2_ip4_dst_port(const uint8_t *b, uint32_t len)
{
	if (len < PD_L2_IP4_MIN_HLEN) return -1;
	const uint32_t ihl = (uint32_t)(b[0] & 0x0Fu) * 4u;
	if (ihl < PD_L2_IP4_MIN_HLEN) return -1;
	if (((((uint32_t)b[6] << 8) | b[7]) & 0x1FFFu) != 0) return -1;   // fragment offset
	if (b[9] != PD_L2_PROTO_UDP && b[9] != PD_L2_PROTO_TCP) return -1;
	if (len < ihl + 4u) return -1;
	return (int32_t)(((uint32_t)b[ihl + 2] << 8) | b[ihl + 3]);
}

// ourIp / mask / gw in host order, 0 = not known yet (the verdict DEFERs).
static inline int pd_l2_classify_ip4(const uint8_t *b, uint32_t len, uint32_t ourIp,
	uint32_t mask, uint32_t gw)
{
	if (len < PD_L2_IP4_MIN_HLEN) return PD_L2_DEFER;
	pd_l2_frame_t f = { ourIp, mask, gw, pd_l2_be32(b + 12), pd_l2_be32(b + 16), 0 };
	if (((((uint32_t)b[6] << 8) | b[7]) & 0x1FFFu) != 0) f.flags |= PD_L2F_NON_FIRST_FRAGMENT;
	const int32_t port = pd_l2_ip4_dst_port(b, len);
	if (port >= 0)
	{
		f.flags |= PD_L2F_IP4_UDP_TCP;
		if (pd_l2_is_service_port(b[9], (uint16_t)port)) f.flags |= PD_L2F_SERVICE_PORT;
	}
	return pd_l2_ingress_verdict(&f);
}

// Would-drop counts since boot: out[0] martian, out[1] wanService.
#define PD_L2_INGRESS_COUNTS 2
#if defined(ESP_PLATFORM)
void pd_l2_ingress_counts(uint32_t out[PD_L2_INGRESS_COUNTS]);   // main/pd_lwip_hooks.c
#endif

#ifdef __cplusplus
}
#endif

#endif // L2_INGRESS_PARSE_H
