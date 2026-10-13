// NvsWriter.cpp -- see NvsWriter.hpp and NvsWriterLogic.hpp (#986 slice 2).
#include "NvsWriter.hpp"

#include <array>
#include <atomic>

#include "PbxPersist.hpp"

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include <cstring>
#include <new>

#include "FlashWriter.hpp"   // #991: the task that drains the queues
#include "PsramAllocator.hpp"   // psram::allocPreferPsram -- the staging slots
#endif

namespace nvswriter
{
namespace
{
	// The staging slots: serialised into under RequestsHandler::_mutex, then
	// copied into the key's queue. Never stack-locals: the callers run on the SIP
	// thread. On the board they are reserved once in start(), in PSRAM where the
	// build has it (the writer never reads them: it reads its own scratch below);
	// the host has no writer task and keeps them static.
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	Slot<kDevicesCap>* s_devices = nullptr;
	Slot<kForwardsCap>* s_forwards = nullptr;
	Slot<kDidMapCap>* s_didmap = nullptr;
#else
	Slot<kDevicesCap> s_devices;
	Slot<kForwardsCap> s_forwards;
	Slot<kDidMapCap> s_didmap;
#endif
	// The writer's own copy of whatever it took, sized to the largest key. The
	// writer is one task and takes one item at a time, so one scratch serves all.
	// A static, so it is internal RAM: it is the buffer the flash write reads, and
	// PSRAM is unreadable while the cache is off (cdr_persist's `blob`, #315).
	Slot<kScratchCap> s_scratch;

	std::array<SlotRef, kKeyCount> slotRefs()
	{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
		return {refOf(*s_devices), refOf(*s_forwards), refOf(*s_didmap)};   // index order == Key
#else
		return {refOf(s_devices), refOf(s_forwards), refOf(s_didmap)};
#endif
	}

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	constexpr const char* kTag = "nvs_writer";

	// The pbxcfg string keys. Key::DidMap has none: it is not one string, and
	// nvsSink() hands it to DidMapping before this is ever asked.
	const char* nvsKeyName(Key k)
	{
		switch (k)
		{
		case Key::Devices:  return "devices";
		case Key::Forwards: return "forwards";
		case Key::DidMap:   break;
		}
		return "?";
	}

	// One zeroed slot from PSRAM, or internal heap if PSRAM is absent or full
	// (allocPreferPsram counts that fallback). Boot only: never on a hot path.
	template <class T>
	T* allocSlot()
	{
		void* p = psram::allocPreferPsram(sizeof(T));
		if (p == nullptr) return nullptr;
		std::memset(p, 0, sizeof(T));
		return ::new (p) T();
	}

	void freeSlots()
	{
		psram::freePreferPsram(s_devices);
		psram::freePreferPsram(s_forwards);
		psram::freePreferPsram(s_didmap);
		s_devices = nullptr;
		s_forwards = nullptr;
		s_didmap = nullptr;
	}

	// One length-1 FreeRTOS queue per key. A queue copies the whole item in under
	// its own short critical section, so the writer can never read a half-written
	// blob and the SIP thread never waits for the writer.
	class QueueTransport
	{
	public:
		bool overwrite(Key k, const void* item)
		{
			const QueueHandle_t h = q[indexOf(k)];
			// A witness, not a guarantee: the writer may take between the two calls.
			const bool replaced = uxQueueMessagesWaiting(h) != 0;
			(void)xQueueOverwrite(h, item);   // length 1: pdPASS by contract, cannot block
			return replaced;
		}
		bool receive(Key k, void* item)
		{
			return xQueueReceive(q[indexOf(k)], item, 0) == pdTRUE;   // never blocks
		}
		bool waiting(Key k) const
		{
			return uxQueueMessagesWaiting(q[indexOf(k)]) != 0;
		}

		std::array<QueueHandle_t, kKeyCount> q{};
		std::array<bool, kKeyCount> hasCaps{};   // which delete the queue needs (CdrRing #476)
	};

	using Transport = QueueTransport;

	std::atomic<bool>& running()
	{
		static std::atomic<bool> r{false};
		return r;
	}
#else
	using Transport = DepthOneMailboxes;
#endif

	Transport& transport()
	{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
		static Transport t;
#else
		static Transport t(slotRefs());
#endif
		return t;
	}

	Stager<Transport>& stagerRef()
	{
		static Stager<Transport> s(transport(), slotRefs(), &s_scratch);
		return s;
	}

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	bool nvsSink(Key k, const char* blob, size_t len)
	{
		if (k == Key::DidMap)
		{
			// Its own namespace and a per-slot sequence, in DidMapping where the
			// keys live. `blob` is the writer's internal scratch, never the slot.
			const bool ok = DidMapping::writeSnapshot(blob, len);
			if (!ok)
			{
				ESP_LOGW(kTag, "DID table not saved (%u bytes)", static_cast<unsigned>(len));
			}
			return ok;
		}
		nvs_handle_t h = 0;
		esp_err_t e = nvs_open(pbxpersist::kNvsNamespace, NVS_READWRITE, &h);
		if (e != ESP_OK)
		{
			ESP_LOGW(kTag, "%s not saved: nvs_open failed (%s)", nvsKeyName(k), esp_err_to_name(e));
			return false;
		}
		e = nvs_set_str(h, nvsKeyName(k), blob);
		if (e == ESP_OK) e = nvs_commit(h);
		nvs_close(h);
		if (e != ESP_OK)
		{
			ESP_LOGW(kTag, "%s not saved (%s, %u bytes)", nvsKeyName(k), esp_err_to_name(e),
				static_cast<unsigned>(len));
			return false;
		}
		return true;
	}

	void deleteQueues(Transport& t)
	{
		for (size_t i = 0; i < kKeyCount; ++i)
		{
			if (t.q[i] == nullptr) continue;
			if (t.hasCaps[i]) vQueueDeleteWithCaps(t.q[i]);
			else              vQueueDelete(t.q[i]);
			t.q[i] = nullptr;
			t.hasCaps[i] = false;
		}
	}
#endif
}

void start()
{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	static bool started = false;   // boot is single-threaded: loadDevices / loadPbxConfig
	if (started) return;
	started = true;
	// Reserved once, here; any failure below unwinds everything and leaves the
	// writer NotRunning, so a stage() can never reach a null slot.
	s_devices = allocSlot<Slot<kDevicesCap>>();
	s_forwards = allocSlot<Slot<kForwardsCap>>();
	s_didmap = allocSlot<Slot<kDidMapCap>>();
	if (s_devices == nullptr || s_forwards == nullptr || s_didmap == nullptr)
	{
		ESP_LOGE(kTag, "staging slot allocation failed -- device table, forwards and DID table will not persist");
		freeSlots();
		started = false;
		return;
	}
	Transport& t = transport();
	const std::array<SlotRef, kKeyCount> refs = slotRefs();
	for (size_t i = 0; i < kKeyCount; ++i)
	{
		// Queue storage in PSRAM where the build has it (CdrRing #315: the writer
		// copies the item into internal RAM before it touches flash), plain
		// internal otherwise, also if PSRAM is exhausted (#476).
#if defined(CONFIG_SPIRAM) && CONFIG_SPIRAM
		t.q[i] = xQueueCreateWithCaps(1, refs[i].itemBytes, MALLOC_CAP_SPIRAM);
		t.hasCaps[i] = (t.q[i] != nullptr);
#endif
		if (t.q[i] == nullptr)
		{
			t.q[i] = xQueueCreate(1, refs[i].itemBytes);
			t.hasCaps[i] = false;
		}
		if (t.q[i] == nullptr)
		{
			ESP_LOGE(kTag, "queue create failed -- device table, forwards and DID table will not persist");
			deleteQueues(t);
			freeSlots();
			started = false;
			return;
		}
	}
	// #991: no task of its own any more. The flash_writer task (FlashWriter.cpp,
	// a plain internal stack, the #277 rule) drains these queues in its pass,
	// round robin with the CDR ring.
	if (!flashwriter::start())
	{
		ESP_LOGE(kTag, "flash_writer task not started -- device table, forwards and DID table will not persist");
		deleteQueues(t);
		freeSlots();
		started = false;
		return;
	}
	// Build the function-static now, not under _mutex on the first *72 (CdrRing's
	// boot-time reasoning), and only once nothing above can fail any more: it
	// keeps the slot pointers. The task may already be running a pass for the CDR
	// ring, but writePending() does not reach the Stager until running is true.
	(void)stagerRef();
	running().store(true, std::memory_order_release);
#endif
}

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
unsigned writePending()
{
	if (!running().load(std::memory_order_acquire)) return 0;   // not started (yet)
	return stagerRef().drainOnce(nvsSink);
}
#endif

StageResult stage(Key k, FunctionRef<void(BlobWriter&)> fill)
{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	if (!running().load(std::memory_order_acquire)) return StageResult::NotRunning;
#endif
	const StageResult r = stagerRef().stage(k, fill);
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	if (r == StageResult::Ok)
	{
		flashwriter::wake();   // #991: never blocks
	}
#endif
	return r;
}

Stats stats()
{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	if (!running().load(std::memory_order_acquire)) return Stats{};   // the Stager does not exist yet
#endif
	return stagerRef().stats();
}

#if !(defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO))
std::string_view stagedForTest(Key k)
{
	return transport().payload(k);
}

unsigned drainForTest(FunctionRef<bool(Key, const char*, size_t)> sink)
{
	return stagerRef().drainOnce(sink);
}

void resetForTest()
{
	transport().clear();
	stagerRef().resetStats();
}
#endif
}
