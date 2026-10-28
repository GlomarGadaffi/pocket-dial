#ifndef L2_GW_PIN_H
#define L2_GW_PIN_H

// ── Gateway MAC pin and per-frame classify (issue #1145) ──────────────────────
//
// The esp_eth input hook (main/pd_eth_ingress.c) learns the gateway's MAC from
// the frames it sees, so the verdict can count an on-link source IP that
// arrives with the gateway's MAC. Counting only: nothing here drops a frame.
//
// The pin has one writer, the Ethernet RX task, and lives in that task's
// state, so it needs no lock. The rule:
//   * A new generation (each GOT_IP, LOST_IP, link up and link down bumps it)
//     resets the pin. That is the only re-pin point.
//   * A frame from the gateway's IP makes its source MAC the candidate. A later
//     frame from that IP with the same MAC pins it; a different MAC first
//     replaces the candidate.
//   * Once pinned, a frame from the gateway's IP with another MAC is counted
//     (gwChanged) and marks the pin changed. The pin is kept, never re-pinned
//     on its own, and while changed the verdict never counts lanGwMac.
//
// The hook reads our IP, mask and gateway through a seqlock (the generation
// is its sequence number); pd_l2_seq_defer() is the reader's retry rule.
//
// pd_l2_eth_classify() fills only the facts known at L2. Emergency, callback,
// trunk-peer, ACL, service-port and own-flow flags stay clear: those are not
// known in the RX task, so a frame is counted before them and nothing here is
// ever used to drop.

#include <stdint.h>

#include "L2FrameFacts.h"
#include "L2IngressVerdict.h"

#ifdef __cplusplus
extern "C" {
#endif

enum
{
	PD_L2_PIN_NONE = 0,
	PD_L2_PIN_CANDIDATE = 1,
	PD_L2_PIN_PINNED = 2,
	PD_L2_PIN_CHANGED = 3,
};

typedef struct
{
	uint32_t gen;     // the generation this state belongs to
	uint8_t state;    // PD_L2_PIN_*
	uint8_t mac[6];   // the candidate, or (pinned/changed) the pinned MAC
} pd_l2_gw_pin_t;

// Seqlock reader: the generation read before and after the snapshot. An odd
// value is a write in progress; a changed one, a write that landed mid-read.
PD_L2_INLINE int pd_l2_seq_defer(uint32_t before, uint32_t after)
{
	return (before & 1u) || before != after;
}

PD_L2_INLINE int pd_l2_mac_eq(const uint8_t *a, const uint8_t *b)
{
	return a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3] && a[4] == b[4] && a[5] == b[5];
}

PD_L2_INLINE void pd_l2_mac_copy(uint8_t *dst, const uint8_t *src)
{
	for (int i = 0; i < 6; ++i) dst[i] = src[i];
}

// Feeds one IPv4 frame. Returns 1 when it counted a gateway MAC change.
PD_L2_INLINE int pd_l2_gw_pin_observe(pd_l2_gw_pin_t *p, uint32_t gen, uint32_t gwIp, uint32_t srcIp,
	const uint8_t *srcMac)
{
	if (p->gen != gen)
	{
		p->gen = gen;
		p->state = PD_L2_PIN_NONE;
	}
	if (!gwIp || srcIp != gwIp) return 0;
	const int same = p->state != PD_L2_PIN_NONE && pd_l2_mac_eq(p->mac, srcMac);
	switch (p->state)
	{
		case PD_L2_PIN_NONE:
			pd_l2_mac_copy(p->mac, srcMac);
			p->state = PD_L2_PIN_CANDIDATE;
			return 0;
		case PD_L2_PIN_CANDIDATE:
			if (same) p->state = PD_L2_PIN_PINNED;
			else pd_l2_mac_copy(p->mac, srcMac);
			return 0;
		case PD_L2_PIN_PINNED:
			if (same) return 0;
			p->state = PD_L2_PIN_CHANGED;
			return 1;
		default:
			return !same;
	}
}

// The verdict's MAC flags for a frame with this source MAC (MAC_VISIBLE is the parser's).
PD_L2_INLINE uint32_t pd_l2_gw_pin_flags(const pd_l2_gw_pin_t *p, const uint8_t *srcMac)
{
	if (p->state < PD_L2_PIN_PINNED) return 0;
	uint32_t flags = PD_L2F_GW_MAC_PINNED;
	if (p->state == PD_L2_PIN_CHANGED) flags |= PD_L2F_GW_MAC_CHANGED;
	if (pd_l2_mac_eq(p->mac, srcMac)) flags |= PD_L2F_SRC_MAC_IS_GW;
	return flags;
}

// One frame: feeds the pin first, then classifies against the updated pin.
// f->ourIp / mask / gateway are the caller's snapshot (host order, 0 = not
// known); the rest of *f is filled here. *gwChanged is 1 when this frame
// counted a gateway MAC change. A frame that does not parse DEFERs.
PD_L2_INLINE int pd_l2_eth_classify(const uint8_t *buf, uint32_t len, uint32_t gen, pd_l2_frame_t *f,
	pd_l2_gw_pin_t *pin, int *gwChanged)
{
	pd_l2_frame_facts_t ff;
	*gwChanged = 0;
	if (!pd_l2_parse_frame(buf, len, &ff)) return PD_L2_DEFER;
	*gwChanged = pd_l2_gw_pin_observe(pin, gen, f->gateway, ff.srcIp, ff.srcMac);
	f->srcIp = ff.srcIp;
	f->dstIp = ff.dstIp;
	f->flags = ff.flags | pd_l2_gw_pin_flags(pin, ff.srcMac);
	return pd_l2_ingress_verdict(f);
}

#ifdef __cplusplus
}
#endif

#endif // L2_GW_PIN_H
