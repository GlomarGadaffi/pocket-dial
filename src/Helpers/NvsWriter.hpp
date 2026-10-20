#pragma once

// NvsWriter -- the process-wide NVS writer (#986 slice 2). The policy is in
// NvsWriterLogic.hpp; this is the sizes, the instance, and (board only) the
// queues, which the flash_writer task drains (#991, FlashWriter.hpp). First
// callers: Registrar::persistDevices() and PbxFeatureConfig::persistForwards(),
// both under RequestsHandler::_mutex.
// Slice 4 adds DidMapping::persist() (Key::DidMap), whose write is not one
// nvs_set_str but DidMapping::writeSnapshot()'s per-slot sequence. #997 adds
// TelephonyApiConfig::persist() (Key::Telephony): the table without its client
// secrets, unpacked by TelephonyApiConfig::writeSnapshot().

#include <cstddef>

#include "DidMapping.hpp"
#include "FunctionRef.hpp"
#include "NvsWriterLogic.hpp"
#include "PoolConfig.hpp"
#include "TelephonyApiConfig.hpp"

namespace nvswriter
{
	// nvs_set_str caps a string at 4000 B including the NUL (CdrRing.hpp makes the
	// same point). The slots are sized to what nvs_set_str could ever have stored,
	// so a blob that now does not fit is one that never persisted before either.
	constexpr size_t kNvsStrMax = 4000;

	// One devices row: mac(12) \t ext(<=64, isValidAor) \t state(1) \t flags(1)
	// \t seq(<=10) \n. Bounded by POCKETDIAL_MAX_CLIENTS rows, plus the NUL.
	constexpr size_t kDevicesRowMax = 12 + 1 + 64 + 1 + 1 + 1 + 1 + 1 + 10 + 1;
	constexpr size_t kDevicesWorstCase = static_cast<size_t>(POCKETDIAL_MAX_CLIENTS) * kDevicesRowMax + 1;
	constexpr size_t kDevicesCap = (kDevicesWorstCase < kNvsStrMax) ? kDevicesWorstCase : kNvsStrMax;

	// Forward targets are not length-checked on the HTTP and config-import paths,
	// so there is no smaller bound than the NVS limit itself.
	constexpr size_t kForwardsCap = kNvsStrMax;

	// The DID table is a fixed-layout snapshot (DidMapping::kSnapshotLen bytes and
	// the NUL), never a string handed to nvs_set_str, so the NVS limit does not
	// apply to it; a field that does not fit its cell is refused at stage time.
	constexpr size_t kDidMapCap = DidMapping::kSnapshotCap;

	// The telephony table without its secrets: also a fixed-layout snapshot (the
	// cells are sized for the longest value TelephonyApiConfig::load() can read).
	constexpr size_t kTelephonyCap = TelephonyApiConfig::kSnapshotCap;

	constexpr size_t maxOf(size_t a, size_t b) { return (a > b) ? a : b; }
	constexpr size_t kScratchCap = maxOf(maxOf(maxOf(kDevicesCap, kForwardsCap), kDidMapCap), kTelephonyCap);

	// What the fourth key costs, as numbers the compiler checks: one staging slot and one
	// queue item of this size each (PSRAM at init on the S3, internal heap on a build
	// without it). It is smaller than the 4,004 B the secret-bearing table was estimated
	// at, and it does not grow the shared scratch, which stays the forwards key's.
	// #1073: 1,564 B before each slot carried its acceptance cell (+112 B).
	static_assert(sizeof(Slot<kTelephonyCap>) == 1676, "the telephony slot and its queue item are 1,676 B each");
	static_assert(kScratchCap == kForwardsCap, "the telephony key must not grow the shared internal scratch");

	// Boot-time and idempotent (loadDevices / loadPbxConfig call it before any
	// handler dispatches). Board: reserves the slots, creates the queues and
	// makes sure the flash_writer task runs (#991, FlashWriter.hpp). Host: nothing.
	void start();

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	// #991: the keys' unit in the flash_writer task's pass: one Stager drainOnce,
	// at most one blob per key. Called only by that task; 0 until start() is done.
	unsigned writePending();
#endif

	// Serialises into the key's staging slot and overwrites the key's queue.
	// Never blocks, never allocates. The caller holds _mutex, which is what makes
	// the staging slot single-producer.
	StageResult stage(Key k, FunctionRef<void(BlobWriter&)> fill);

	Stats stats();

#if !(defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO))
	// Host test seams: the writer task does not exist here, so a test plays it.
	std::string_view stagedForTest(Key k);                                       // payload waiting, or empty
	unsigned drainForTest(FunctionRef<bool(Key, const char*, size_t)> sink);     // one writer pass
	void resetForTest();                                                         // empty queues, zero counters

	// #997: which writer buffers hold `needle` right now, anywhere in them (the whole
	// slot, the whole queue item, the whole scratch, not just the payload a stage
	// wrote): a slot keeps its last bytes until the next stage overwrites them, a queue
	// item keeps them after the writer took it, and so does the scratch.
	enum BufferBit : unsigned { InSlot = 1, InQueue = 2, InScratch = 4 };
	unsigned buffersHoldingForTest(std::string_view needle);
#endif
}
