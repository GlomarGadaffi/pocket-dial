// Issue #496 / #509 review: the LWIP_HOOK_IP4_INPUT implementation. The
// decision is pd_ip4_input_verdict() (src/Helpers/Ip4InputGuard.h, host-tested);
// this file only applies it to a live pbuf. Runs in the tcpip thread, with the
// lwIP core lock held, before ip4_input() trims the pbuf. Allocates nothing.
// tools/check_lwip_ip4_hook.cmake fails the build if ip4.c does not call it.

#include "lwip/opt.h"
#include "lwip/pbuf.h"
#include "lwip/netif.h"
#include "lwip/prot/ip4.h"
#include "lwip/def.h"
#include "esp_log.h"

#include "Ip4InputGuard.h"
#include "L2IngressParse.h"
#include "lwip_hooks/pd_lwip_hooks.h"

static uint32_t s_padded;          // see pd_ip4_guard_counts(); written only here
static uint32_t s_tinyFragments;
static uint32_t s_mdnsFragments;   // #559

void pd_ip4_guard_counts(uint32_t out[3])
{
	out[2] = __atomic_load_n(&s_mdnsFragments, __ATOMIC_RELAXED);
	out[0] = __atomic_load_n(&s_padded, __ATOMIC_RELAXED);
	out[1] = __atomic_load_n(&s_tinyFragments, __ATOMIC_RELAXED);
}

// #1145: would-drop counts (L2IngressParse.h), out[0] martian, out[1] wanService.
// Count only: nothing here frees or returns 1.
static uint32_t s_l2Ingress[PD_L2_INGRESS_COUNTS];

void pd_l2_ingress_counts(uint32_t out[PD_L2_INGRESS_COUNTS])
{
	for (int i = 0; i < PD_L2_INGRESS_COUNTS; ++i)
		out[i] = __atomic_load_n(&s_l2Ingress[i], __ATOMIC_RELAXED);
}

// ip4_input() holds the lwIP core lock here (LWIP_ASSERT_CORE_LOCKED; with
// IDF's default config this is the tcpip thread itself), and that lock owns
// the netif, so its address fields are plain reads. No esp_netif getter: the
// hook stays on plain field reads. Taken before the
// checksum check, so lwIP may still drop a frame counted here.
static void pd_l2_count(const struct pbuf *p, const struct netif *inp)
{
	if (inp == NULL) return;
	const int v = pd_l2_classify_ip4((const uint8_t *)p->payload, p->len,
		lwip_ntohl(ip4_addr_get_u32(netif_ip4_addr(inp))),
		lwip_ntohl(ip4_addr_get_u32(netif_ip4_netmask(inp))),
		lwip_ntohl(ip4_addr_get_u32(netif_ip4_gw(inp))));
	if (v == PD_L2_WOULD_DROP_MARTIAN)
		__atomic_fetch_add(&s_l2Ingress[0], 1u, __ATOMIC_RELAXED);
	else if (v == PD_L2_WOULD_DROP_WAN_SERVICE)
		__atomic_fetch_add(&s_l2Ingress[1], 1u, __ATOMIC_RELAXED);
}

int pd_ip4_input_hook(struct pbuf *p, struct netif *inp)
{
	if (p == NULL || p->len < IP_HLEN) return 0;   // lwIP's own checks drop it
	const struct ip_hdr *iphdr = (const struct ip_hdr *)p->payload;

	switch (pd_ip4_input_verdict(p->tot_len, lwip_ntohs(IPH_LEN(iphdr)), IPH_HL_BYTES(iphdr),
		(lwip_ntohs(IPH_OFFSET(iphdr)) & IP_MF) != 0))
	{
		case PD_IP4_DROP_PADDED:
			// First of each kind since boot, so a flood leaves one line, not a storm.
			if (__atomic_fetch_add(&s_padded, 1u, __ATOMIC_RELAXED) == 0)
				ESP_LOGW("ip4guard", "over-padded frame dropped (#496; counted in /api/status ip4Guard)");
			pbuf_free(p);
			return 1;
		case PD_IP4_DROP_TINY_FRAGMENT:
			if (__atomic_fetch_add(&s_tinyFragments, 1u, __ATOMIC_RELAXED) == 0)
				ESP_LOGW("ip4guard", "short non-final fragment dropped (#496; counted in /api/status ip4Guard)");
			pbuf_free(p);
			return 1;
		default:
			break;
	}
	{
		const u16_t off = lwip_ntohs(IPH_OFFSET(iphdr));
		if (pd_ip4_is_mdns_fragment(lwip_ntohl(iphdr->dest.addr), (off & IP_MF) != 0,
			(uint32_t)(off & IP_OFFMASK) * 8u))
		{
			if (__atomic_fetch_add(&s_mdnsFragments, 1u, __ATOMIC_RELAXED) == 0)
				ESP_LOGW("ip4guard", "fragmented mDNS datagram dropped (#559; counted in /api/status ip4Guard)");
			pbuf_free(p);
			return 1;
		}
		pd_l2_count(p, inp);
		return 0;
	}
}
