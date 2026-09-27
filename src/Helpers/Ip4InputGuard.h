#ifndef IP4_INPUT_GUARD_H
#define IP4_INPUT_GUARD_H

// ── IPv4 input guard (issue #496, #509 review) ────────────────────────────────
//
// With IPv4 reassembly on, SO_RCVBUF (UdpRcvBuf.hpp) caps what a UDP socket
// may queue, but it counts p->tot_len: the IP payload AFTER ip4_input() trims
// the pbuf to IPH_LEN. The memory a received pbuf pins is the DRIVER's buffer:
//   - W5500 / ESP32 EMAC: a malloc of the whole frame, wrapped as a PBUF_REF
//     custom pbuf (esp_netif esp_pbuf_ref.c). pbuf_realloc() cannot shrink it.
//   - Wi-Fi: a fixed ~1.6 KB driver RX buffer, whatever the frame's length.
// ip_reass() chains fragments with pbuf_cat, no copy. So ten 1,514 B frames
// each padded around ~72 B of IP payload passed a 32 KB cap while pinning
// ~15 KB per datagram -- ~500 KB per socket at 32 queued datagrams, a DoS
// that main (which drops every fragment) does not have.
//
// The guard runs in LWIP_HOOK_IP4_INPUT, BEFORE the trim (ip4.c), and decides
// from the header alone:
//   - Ethernet pads a short frame up to 46 B of payload and never further, so
//     a frame longer than max(IPH_LEN, 46) (+4 B slack for a driver that keeps
//     the FCS) carries padding no real stack sends: DROP.
//   - A NON-final fragment under kMinNonFinalFragmentPayload is not what any
//     real sender produces (they fragment at the path MTU; IPv4's minimum
//     reassembly size is 576) but is the cheapest way to multiply per-pbuf
//     overhead against the byte cap: DROP.
//   - Any other fragment that sits in a driver-owned (custom) pbuf is COPIED
//     into a right-sized PBUF_RAM and the driver buffer released at once, so
//     what reassembly and the socket queue pin is what SO_RCVBUF counts.
//   - Everything else (every unfragmented datagram) PASSes untouched.
//
// Pure and dependency-free so the host suite can pin every branch; the lwIP
// hook itself (main/pd_lwip_hooks.c) is ESP-only.

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum
{
	PD_IP4_PASS = 0,
	PD_IP4_DROP_PADDED = 1,
	PD_IP4_DROP_TINY_FRAGMENT = 2,
	PD_IP4_CLONE = 3,
};

// Smallest IP payload a non-final fragment may carry. Real stacks fragment at
// the path MTU (1,480 B on Ethernet); 512 leaves room for a 576-byte path.
#define PD_IP4_MIN_NONFINAL_FRAGMENT_PAYLOAD 512u
// Ethernet's minimum payload: shorter frames are padded up to it.
#define PD_IP4_MIN_ETH_PAYLOAD 46u
// Tolerated trailer beyond that (a driver that leaves the 4-byte FCS on).
#define PD_IP4_TRAILER_SLACK 4u

// totLen: bytes in the received pbuf chain (IP header onward, untrimmed).
// ipLen / ipHdrLen: IPH_LEN and IPH_HL in bytes. moreFragments / fragOffset:
// IP_MF and the fragment offset in bytes. driverOwned: PBUF_FLAG_IS_CUSTOM.
static inline int pd_ip4_input_verdict(uint32_t totLen, uint32_t ipLen, uint32_t ipHdrLen,
	int moreFragments, uint32_t fragOffset, int driverOwned)
{
	const uint32_t allowed = ipLen > PD_IP4_MIN_ETH_PAYLOAD ? ipLen : PD_IP4_MIN_ETH_PAYLOAD;
	if (totLen > allowed + PD_IP4_TRAILER_SLACK) return PD_IP4_DROP_PADDED;
	if (!moreFragments && fragOffset == 0) return PD_IP4_PASS;
	if (moreFragments && ipLen < ipHdrLen + PD_IP4_MIN_NONFINAL_FRAGMENT_PAYLOAD)
		return PD_IP4_DROP_TINY_FRAGMENT;
	return driverOwned ? PD_IP4_CLONE : PD_IP4_PASS;
}

#if defined(ESP_PLATFORM)
// Counts since boot, indexed by the verdicts above (PASS is not counted);
// [PD_IP4_CLONE] counts successful copies, [0] counts copies that failed for
// want of memory (the fragment is then dropped). main/pd_lwip_hooks.c.
void pd_ip4_guard_counts(uint32_t out[4]);
#endif

#ifdef __cplusplus
}
#endif

#endif // IP4_INPUT_GUARD_H
