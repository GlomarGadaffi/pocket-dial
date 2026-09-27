#ifndef IP4_INPUT_GUARD_H
#define IP4_INPUT_GUARD_H

// ── IPv4 input guard (issue #496, #509 review) ────────────────────────────────
//
// With IPv4 reassembly on, SO_RCVBUF (UdpRcvBuf.hpp) caps what a UDP socket
// may queue, but it counts p->tot_len: the IP payload AFTER ip4_input() trims
// the pbuf to IPH_LEN. The memory a received pbuf pins is the DRIVER's buffer,
// a malloc of the frame as received wrapped as a PBUF_REF custom pbuf
// (esp_netif esp_pbuf_ref.c), which pbuf_realloc() cannot shrink; and
// ip_reass() chains fragments with pbuf_cat, no copy. So ten 1,514 B frames
// each padded around ~72 B of IP payload passed a 32 KB cap while pinning
// ~15 KB per datagram -- ~500 KB per socket at 32 queued datagrams, a DoS
// that main (which drops every fragment) does not have.
//
// Both Ethernet drivers (W5500, ESP32 EMAC) and IDF's dynamic Wi-Fi RX
// buffers allocate the frame's own length, so once padding is refused the
// bytes a pbuf pins track the bytes SO_RCVBUF counts. The guard runs in
// LWIP_HOOK_IP4_INPUT, BEFORE the trim (ip4.c), and decides from the header:
//   - Ethernet pads a short frame up to 46 B of payload and never further, so
//     a frame longer than max(IPH_LEN, 46) (+4 B slack for a driver that keeps
//     the FCS) carries padding no real stack sends: DROP.
//   - A NON-final fragment under PD_IP4_MIN_NONFINAL_FRAGMENT_PAYLOAD is the
//     cheapest way to multiply per-pbuf overhead against the byte cap: DROP.
//     Senders fragment at the path MTU, so this is rare legitimately -- but not
//     impossible: a router re-fragmenting an already-fragmented datagram onto
//     a smaller-MTU link can leave a short non-final piece. Such a datagram is
//     lost (and counted), not silently.
//   - Everything else PASSes untouched. No copy: a copy would allocate on the
//     RX path for every fragment, and with padding refused it buys nothing.
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
};

// Smallest IP payload a non-final fragment may carry. Ethernet fragments at
// 1,480 B; 256 bounds the per-fragment overhead against SO_RCVBUF at ~1.3x.
#define PD_IP4_MIN_NONFINAL_FRAGMENT_PAYLOAD 256u
// Ethernet's minimum payload: shorter frames are padded up to it.
#define PD_IP4_MIN_ETH_PAYLOAD 46u
// Tolerated trailer beyond that (a driver that leaves the 4-byte FCS on).
#define PD_IP4_TRAILER_SLACK 4u

// totLen: bytes in the received pbuf chain (IP header onward, untrimmed).
// ipLen / ipHdrLen: IPH_LEN and IPH_HL in bytes. moreFragments: IP_MF.
static inline int pd_ip4_input_verdict(uint32_t totLen, uint32_t ipLen, uint32_t ipHdrLen,
	int moreFragments)
{
	const uint32_t allowed = ipLen > PD_IP4_MIN_ETH_PAYLOAD ? ipLen : PD_IP4_MIN_ETH_PAYLOAD;
	if (totLen > allowed + PD_IP4_TRAILER_SLACK) return PD_IP4_DROP_PADDED;
	if (moreFragments && ipLen < ipHdrLen + PD_IP4_MIN_NONFINAL_FRAGMENT_PAYLOAD)
		return PD_IP4_DROP_TINY_FRAGMENT;
	return PD_IP4_PASS;
}

#if defined(ESP_PLATFORM)
// Drops since boot: out[0] padded frames, out[1] tiny non-final fragments.
// main/pd_lwip_hooks.c.
void pd_ip4_guard_counts(uint32_t out[2]);
#endif

#ifdef __cplusplus
}
#endif

#endif // IP4_INPUT_GUARD_H
