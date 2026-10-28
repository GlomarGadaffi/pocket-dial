#ifndef PD_ETH_INGRESS_H
#define PD_ETH_INGRESS_H

// Issue #1145: the count-only esp_eth input-path hook (pd_eth_ingress.c).
// Every frame is forwarded to the netif unchanged; this only counts.

#include <stdint.h>

#include "esp_err.h"
#include "esp_eth_driver.h"
#include "esp_netif.h"

#ifdef __cplusplus
extern "C" {
#endif

enum
{
	PD_ETH_INGRESS_LAN_GW_MAC = 0,  // on-link source IP with the gateway's MAC
	PD_ETH_INGRESS_GW_CHANGED = 1,  // gateway-IP frames with a MAC other than the pinned one
	PD_ETH_INGRESS_FRAMES = 2,      // frames seen
	PD_ETH_INGRESS_MAX_CYCLES = 3,  // most CPU cycles one classification took
	PD_ETH_INGRESS_NCOUNTS = 4,
};

// Replaces the glue's input path with the hook. Call after esp_netif_attach()
// (which installs the glue's own) and before esp_eth_start().
esp_err_t pd_eth_ingress_install(esp_eth_handle_t eth, esp_netif_t *netif);

// Our IP, mask and gateway from IP_EVENT_ETH_GOT_IP; NULL on IP_EVENT_ETH_LOST_IP.
void pd_eth_ingress_set_ip(const esp_netif_ip_info_t *info);

// Link up or down: a new generation, so the gateway MAC is learned again.
void pd_eth_ingress_link_event(void);

void pd_eth_ingress_counts(uint32_t out[PD_ETH_INGRESS_NCOUNTS]);

#ifdef __cplusplus
}
#endif

#endif // PD_ETH_INGRESS_H
