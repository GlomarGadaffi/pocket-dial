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
#include "lwip_hooks/pd_lwip_hooks.h"

static uint32_t s_padded;          // see pd_ip4_guard_counts(); written only here
static uint32_t s_tinyFragments;

void pd_ip4_guard_counts(uint32_t out[2])
{
	out[0] = __atomic_load_n(&s_padded, __ATOMIC_RELAXED);
	out[1] = __atomic_load_n(&s_tinyFragments, __ATOMIC_RELAXED);
}

int pd_ip4_input_hook(struct pbuf *p, struct netif *inp)
{
	(void)inp;
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
			return 0;
	}
}
