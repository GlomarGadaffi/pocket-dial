// Issue #1145: a count-only hook on the esp_eth input path. It replaces the
// netif glue's eth_input_to_netif (esp_eth_netif_glue.c) and does what that
// does, esp_netif_receive(), after counting. Nothing is dropped or changed.
//
// Runs in the Ethernet RX task (w5500_tsk or emac_rx, 4096 B stacks) for every
// frame: IRAM, lock-free, allocation-free, no per-frame logging. The decision
// is pd_l2_eth_classify() (src/Helpers/L2GwPin.h, host-tested). Emergency,
// callback, trunk, ACL and own-flow facts are not known here and stay clear,
// so a frame is counted before them; the count is never used to drop.
// Martian and WAN-service frames are counted by the IPv4 hook
// (pd_lwip_hooks.c), not here. tools/check_eth_input_hook.cmake fails the build
// if the eth mains stop installing it.
//
// Buffer ownership: esp_netif_receive() always takes buf. lwIP's
// ethernetif_input() frees it on every error path and hands it to a pbuf
// otherwise, and both MAC drivers ignore the return. So the hook forwards
// exactly once and never frees or touches buf after forwarding.

#include "pd_eth_ingress.h"

#include "esp_attr.h"
#include "esp_cpu.h"
#include "esp_log.h"
#include "lwip/def.h"
#include "sdkconfig.h"

#include "L2GwPin.h"

// The glue's input path also runs the L2 TAP filter; this one does not.
#if CONFIG_ESP_NETIF_L2_TAP
#error "pd_eth_ingress replaces the glue input path, which CONFIG_ESP_NETIF_L2_TAP needs"
#endif

static const char *TAG = "eth_ingress";

// Our IP, mask, gateway (host order) behind a seqlock. One writer, the default
// event loop task; the RX task reads. gen is odd while a write is in progress.
static struct
{
	uint32_t gen, ip, mask, gw;
} s_ip;

static pd_l2_gw_pin_t s_pin;   // RX task only

static uint32_t s_counts[PD_ETH_INGRESS_NCOUNTS];   // written only by the RX task

static void publish(uint32_t ip, uint32_t mask, uint32_t gw)
{
	const uint32_t g = __atomic_load_n(&s_ip.gen, __ATOMIC_RELAXED);
	__atomic_store_n(&s_ip.gen, g + 1, __ATOMIC_RELAXED);
	__atomic_thread_fence(__ATOMIC_RELEASE);
	__atomic_store_n(&s_ip.ip, ip, __ATOMIC_RELAXED);
	__atomic_store_n(&s_ip.mask, mask, __ATOMIC_RELAXED);
	__atomic_store_n(&s_ip.gw, gw, __ATOMIC_RELAXED);
	__atomic_store_n(&s_ip.gen, g + 2, __ATOMIC_RELEASE);
}

void pd_eth_ingress_set_ip(const esp_netif_ip_info_t *info)
{
	if (info == NULL) publish(0, 0, 0);
	else publish(lwip_ntohl(info->ip.addr), lwip_ntohl(info->netmask.addr), lwip_ntohl(info->gw.addr));
}

void pd_eth_ingress_link_event(void)
{
	publish(__atomic_load_n(&s_ip.ip, __ATOMIC_RELAXED), __atomic_load_n(&s_ip.mask, __ATOMIC_RELAXED),
		__atomic_load_n(&s_ip.gw, __ATOMIC_RELAXED));
}

void pd_eth_ingress_counts(uint32_t out[PD_ETH_INGRESS_NCOUNTS])
{
	for (int i = 0; i < PD_ETH_INGRESS_NCOUNTS; ++i) out[i] = __atomic_load_n(&s_counts[i], __ATOMIC_RELAXED);
}

static inline __attribute__((always_inline)) void count(int which)
{
	__atomic_fetch_add(&s_counts[which], 1u, __ATOMIC_RELAXED);
}

// Snapshot our state, then classify. A torn snapshot defers the frame.
static void IRAM_ATTR classify(const uint8_t *buf, uint32_t len)
{
	pd_l2_frame_t f = {0};
	const uint32_t gen = __atomic_load_n(&s_ip.gen, __ATOMIC_ACQUIRE);
	f.ourIp = __atomic_load_n(&s_ip.ip, __ATOMIC_RELAXED);
	f.mask = __atomic_load_n(&s_ip.mask, __ATOMIC_RELAXED);
	f.gateway = __atomic_load_n(&s_ip.gw, __ATOMIC_RELAXED);
	__atomic_thread_fence(__ATOMIC_ACQUIRE);
	if (pd_l2_seq_defer(gen, __atomic_load_n(&s_ip.gen, __ATOMIC_RELAXED))) return;

	int gwChanged = 0;
	const int verdict = pd_l2_eth_classify(buf, len, gen, &f, &s_pin, &gwChanged);
	if (gwChanged) count(PD_ETH_INGRESS_GW_CHANGED);
	if (verdict == PD_L2_WOULD_DROP_LAN_GW_MAC) count(PD_ETH_INGRESS_LAN_GW_MAC);
}

// Times classify() and keeps the max. The RX task is not pinned and the cycle
// counter is per core, so a sample that migrated cores is skipped.
static void IRAM_ATTR observe(const uint8_t *buf, uint32_t len)
{
	count(PD_ETH_INGRESS_FRAMES);
	const int core = esp_cpu_get_core_id();
	const uint32_t t0 = esp_cpu_get_cycle_count();
	classify(buf, len);
	const uint32_t dt = esp_cpu_get_cycle_count() - t0;
	if (esp_cpu_get_core_id() != core) return;
	if (dt > __atomic_load_n(&s_counts[PD_ETH_INGRESS_MAX_CYCLES], __ATOMIC_RELAXED))
		__atomic_store_n(&s_counts[PD_ETH_INGRESS_MAX_CYCLES], dt, __ATOMIC_RELAXED);
}

// Same signature and priv (the esp_netif) as the glue's eth_input_to_netif.
esp_err_t IRAM_ATTR pd_eth_ingress_input(esp_eth_handle_t eth, uint8_t *buf, uint32_t len, void *priv, void *info)
{
	(void)eth;
	(void)info;
	observe(buf, len);
	return esp_netif_receive((esp_netif_t *)priv, buf, len, NULL);
}

esp_err_t pd_eth_ingress_install(esp_eth_handle_t eth, esp_netif_t *netif)
{
	const esp_err_t err = esp_eth_update_input_path_info(eth, pd_eth_ingress_input, netif);
	if (err == ESP_OK) ESP_LOGI(TAG, "esp_eth input hook installed (count only, #1145)");
	return err;
}
