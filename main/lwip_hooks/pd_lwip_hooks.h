#ifndef PD_LWIP_HOOKS_H
#define PD_LWIP_HOOKS_H

// Included into lwIP's own sources through ESP_IDF_LWIP_HOOK_FILENAME (set on
// the lwip component in the top-level CMakeLists.txt). Keep it to forward
// declarations: every lwIP .c file that includes the hook file sees this.
// Issue #496 / #509 review: see src/Helpers/Ip4InputGuard.h.

#ifdef __cplusplus
extern "C" {
#endif

struct pbuf;
struct netif;

// Returns non-zero when it consumed (freed, or re-injected a copy of) `p`.
int pd_ip4_input_hook(struct pbuf *p, struct netif *inp);

#define LWIP_HOOK_IP4_INPUT(p, inp) pd_ip4_input_hook((p), (inp))

#ifdef __cplusplus
}
#endif

#endif // PD_LWIP_HOOKS_H
