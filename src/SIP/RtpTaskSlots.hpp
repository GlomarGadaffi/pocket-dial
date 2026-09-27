#ifndef PD_RTP_TASK_SLOTS_HPP
#define PD_RTP_TASK_SLOTS_HPP

// Issue #479: every RtpSender / RtpReceiver object is a media-task SLOT. Its
// stack + TCB are allocated once, in the constructor, and each stream's task is
// created with xTaskCreateStaticPinnedToCore on that memory (never the heap on
// the call path). The objects are fixed members sized by the PoolConfig caps,
// so the cost is fixed too:
//   rtp_media_tx: internal DMA-capable RAM (the W5500 driver passes stack
//                 buffers to a DMA SPI bus -- #466), kTxSlots x kStackBytes;
//   rtp_media_rx: PSRAM (internal fallback where there is none), kRxSlots x
//                 kStackBytes.
// The conference room is built in the RequestsHandler constructor, so its legs'
// slots are boot-time too. tests/tools/test_rtp_static_slots.py gates all this.

#include <cstdint>

#include "PoolConfig.hpp"

namespace pd
{
	namespace rtpslots
	{
		constexpr uint32_t kStackBytes = 6144;   // lwIP send/recv + tone synth / sink headroom

		// _rtpSender + _anchorRtpSenders + _vmRtpSenders + conference legs.
		constexpr uint32_t kTxSlots = 1 + POCKETDIAL_MAX_ANCHOR_CALLS
			+ POCKETDIAL_MAX_VOICEMAIL_LEGS + POCKETDIAL_CONF_LEGS;
		// _anchorRtpReceivers + _vmRtpReceivers + _trunkRx + _handsetRx + conference legs.
		constexpr uint32_t kRxSlots = POCKETDIAL_MAX_ANCHOR_CALLS
			+ POCKETDIAL_MAX_VOICEMAIL_LEGS + 2 * POCKETDIAL_MAX_TRUNK_CALLS + POCKETDIAL_CONF_LEGS;

		constexpr uint32_t kTxInternalBytes = kTxSlots * kStackBytes;
		constexpr uint32_t kRxPsramBytes    = kRxSlots * kStackBytes;
	}
}

// The no-PSRAM boot budget (slots + the conference room) is static_asserted in
// ConferenceRoom.hpp, which knows sizeof(ConferenceRoom).

#endif // PD_RTP_TASK_SLOTS_HPP
