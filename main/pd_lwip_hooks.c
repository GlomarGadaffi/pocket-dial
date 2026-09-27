// Issue #496 / #509 review: the LWIP_HOOK_IP4_INPUT implementation. The
// decision is pd_ip4_input_verdict() (src/Helpers/Ip4InputGuard.h, host-tested);
// this file only applies it to a live pbuf. Runs in the tcpip thread, with the
// lwIP core lock held, before ip4_input() trims the pbuf.

#include "lwip/opt.h"
#include "lwip/pbuf.h"
#include "lwip/netif.h"
#include "lwip/ip4.h"
#include "lwip/prot/ip4.h"
#include "lwip/def.h"
#include "esp_log.h"

#include "Ip4InputGuard.h"
#include "lwip_hooks/pd_lwip_hooks.h"

static uint32_t s_counts[4];   // see pd_ip4_guard_counts(); written only here

static void count(int idx)
{
	if (__atomic_fetch_add(&s_counts[idx], 1u, __ATOMIC_RELAXED) == 0)
	{
		// First of each kind since boot, so a flood leaves one line, not a storm.
		static const char *const kWhat[4] = {
			"fragment copy failed (no memory), dropped",
			"over-padded frame dropped",
			"tiny non-final fragment dropped",
			"driver-owned fragment copied",
		};
		ESP_LOGW("ip4guard", "%s (#496; counted in /api/status ip4Guard)", kWhat[idx]);
	}
}

void pd_ip4_guard_counts(uint32_t out[4])
{
	for (int i = 0; i < 4; ++i) out[i] = __atomic_load_n(&s_counts[i], __ATOMIC_RELAXED);
}

int pd_ip4_input_hook(struct pbuf *p, struct netif *inp)
{
	if (p == NULL || p->len < IP_HLEN) return 0;   // lwIP's own checks drop it
	const struct ip_hdr *iphdr = (const struct ip_hdr *)p->payload;
	const u16_t off = lwip_ntohs(IPH_OFFSET(iphdr));

	const int verdict = pd_ip4_input_verdict(p->tot_len, lwip_ntohs(IPH_LEN(iphdr)),
		IPH_HL_BYTES(iphdr), (off & IP_MF) != 0, (uint32_t)(off & IP_OFFMASK) * 8u,
		(p->flags & PBUF_FLAG_IS_CUSTOM) != 0);

	switch (verdict)
	{
		case PD_IP4_DROP_PADDED:
		case PD_IP4_DROP_TINY_FRAGMENT:
			count(verdict);
			pbuf_free(p);
			return 1;
		case PD_IP4_CLONE:
		{
			// A right-sized PBUF_RAM copy; the driver's buffer goes back now.
			// The copy re-enters ip4_input() and so this hook, where it is no
			// longer driver-owned and passes.
			struct pbuf *q = pbuf_clone(PBUF_RAW, PBUF_RAM, p);
			pbuf_free(p);
			if (q == NULL)
			{
				count(0);
				return 1;
			}
			count(PD_IP4_CLONE);
			ip4_input(q, inp);
			return 1;
		}
		default:
			return 0;
	}
}
