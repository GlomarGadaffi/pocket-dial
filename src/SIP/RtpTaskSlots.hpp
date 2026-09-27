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

#if defined(ESP_PLATFORM)
#include "sdkconfig.h"
#if !defined(CONFIG_SPIRAM) || !CONFIG_SPIRAM
// No PSRAM (esp32_constrained): the rx stacks fall back to internal too, so
// every slot is internal DRAM, fixed at boot. SIP_CONSTRAINED's caps
// (main/CMakeLists.txt) give 11 slots = 66 KB; the defaults would be 150 KB.
static_assert((pd::rtpslots::kTxSlots + pd::rtpslots::kRxSlots) * pd::rtpslots::kStackBytes
              <= 72u * 1024u,
              "#479: no-PSRAM build fixes too much internal DRAM in RTP task slots; "
              "build with SIP_CONSTRAINED=1 or lower the POCKETDIAL_* call caps");
#endif
#endif

#endif // PD_RTP_TASK_SLOTS_HPP
