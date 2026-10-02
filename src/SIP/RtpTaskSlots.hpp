#ifndef PD_RTP_TASK_SLOTS_HPP
#define PD_RTP_TASK_SLOTS_HPP

// Issue #479: every RtpSender / RtpReceiver object is a media-task SLOT. Its
// stack + TCB are allocated once, in the constructor, and each stream's task is
// created with xTaskCreateStaticPinnedToCore on that memory (never the heap on
// the call path). The objects are fixed members sized by the PoolConfig caps,
// so the cost is fixed too:
//   rtp_media_tx: internal DMA-capable RAM (the W5500 driver passes stack
//                 buffers to a DMA SPI bus -- #466), kTxSlots x kTxStackBytes, one pool shared by all senders;
//   rtp_media_rx: PSRAM (internal fallback where there is none), kRxSlots x
//                 kRxStackBytes, one per receiver.
// The conference room (POCKETDIAL_CONFERENCE) is built in the RequestsHandler
// constructor, so its legs' slots are boot-time too; with it off there are none.
// The multicast pager's receiver (POCKETDIAL_MULTICAST_PAGING) is a RequestsHandler
// member, so its slot is boot-time as well.
// tests/tools/test_rtp_static_slots.py gates all this.

#include <cstdint>

#include "PoolConfig.hpp"

namespace pd
{
	namespace rtpslots
	{
		// Measured on .244 (#598, BigDog2): rtp_media_tx min free 4212 of 6144, so
		// ~1.9 KB used; 3072 keeps >= 1 KB margin. Trunk legs relay through
		// RtpReceiver::sendRaw (rx objects), so no trunk path runs on this stack.
		// rtp_media_rx min free 1464 of 6144 (~4.7 KB used): stays 6144.
		constexpr uint32_t kTxStackBytes = 3072;
		constexpr uint32_t kRxStackBytes = 6144;
		constexpr uint32_t kConfSlots  = POCKETDIAL_CONFERENCE ? POCKETDIAL_CONF_LEGS : 0;
		// #800: the multicast pager's one receiver (RequestsHandler::_mcastRx).
		constexpr uint32_t kMcastPageSlots = POCKETDIAL_MULTICAST_PAGING ? 1 : 0;

		// Option D (desmo): tx stacks are one shared pool sized to the concurrent
		// media streams, not one per RtpSender object; a full pool refuses (counted).
		constexpr uint32_t kTxSlots = POCKETDIAL_RTP_TX_POOL;
		// Receivers keep one slot each (PSRAM): _anchorRtpReceivers + _vmRtpReceivers
		// + _trunkRx + _handsetRx + conference legs + the multicast pager.
		constexpr uint32_t kRxSlots = POCKETDIAL_MAX_ANCHOR_CALLS
			+ POCKETDIAL_MAX_VOICEMAIL_LEGS + 2 * POCKETDIAL_MAX_TRUNK_CALLS + kConfSlots
			+ kMcastPageSlots;

		constexpr uint32_t kTxInternalBytes = kTxSlots * kTxStackBytes;
		constexpr uint32_t kRxPsramBytes    = kRxSlots * kRxStackBytes;
		// #479 A (#661): each anchor CallSlot's tel_media_rx stack is boot-allocated too.
		constexpr uint32_t kAnchorRxStackBytes = 6144;
		constexpr uint32_t kAnchorRxBytes      = POCKETDIAL_MAX_ANCHOR_CALLS * kAnchorRxStackBytes;
		// #479: the conference room's one mix-tick task (conf_mix_tick) is a boot
		// allocation too: 3 KB internal (+ its TCB), only when a room is built.
		// Not in the no-PSRAM 72 KB budget above, which builds no room.
		constexpr uint32_t kConfMixStackBytes  = 3072;
	}
}

#if defined(ESP_PLATFORM)
#include "sdkconfig.h"
#if !defined(CONFIG_SPIRAM) || !CONFIG_SPIRAM
// No PSRAM (esp32_constrained): rx stacks fall back to internal too, so every
// slot is internal DRAM, fixed at boot. SIP_CONSTRAINED (no conference, tx
// pool 3): 3 x 3 KB tx + 4 x 6 KB rx + 1 x 6 KB anchor tel_media_rx = 39 KB.
// No conference room here.
static_assert(!POCKETDIAL_CONFERENCE,
              "#479: no conference room on a no-PSRAM build (SIP_CONSTRAINED sets "
              "POCKETDIAL_CONFERENCE=0)");
static_assert(pd::rtpslots::kTxInternalBytes + pd::rtpslots::kRxPsramBytes
              + pd::rtpslots::kAnchorRxBytes <= 72u * 1024u,
              "#479: no-PSRAM build fixes too much internal DRAM in RTP/anchor task slots; "
              "build with SIP_CONSTRAINED=1 or lower the POCKETDIAL_* call caps");
#endif
#endif

#endif // PD_RTP_TASK_SLOTS_HPP
