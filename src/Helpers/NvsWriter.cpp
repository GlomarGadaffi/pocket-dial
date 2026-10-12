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

#include "PsramAllocator.hpp"   // psram::allocPreferPsram -- the staging slots
#include "PsramTask.hpp"   // PD_ASSERT_NOT_PSRAM_STACK -- issue #277
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
#else
	Slot<kDevicesCap> s_devices;
	Slot<kForwardsCap> s_forwards;
#endif
	// The writer's own copy of whatever it took, sized to the largest key. The
	// writer is one task and takes one item at a time, so one scratch serves all.
	// A static, so it is internal RAM: it is the buffer the flash write reads, and
	// PSRAM is unreadable while the cache is off (cdr_persist's `blob`, #315).
	Slot<kScratchCap> s_scratch;

	std::array<SlotRef, kKeyCount> slotRefs()
	{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
		return {refOf(*s_devices), refOf(*s_forwards)};   // index order == Key
#else
		return {refOf(s_devices), refOf(s_forwards)};
#endif
	}

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	constexpr const char* kTag = "nvs_writer";

	const char* nvsKeyName(Key k)
	{
		return (k == Key::Devices) ? "devices" : "forwards";
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
		s_devices = nullptr;
		s_forwards = nullptr;
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
	std::atomic<TaskHandle_t>& writerHandle()
	{
		static std::atomic<TaskHandle_t> h{nullptr};
		return h;
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

	// PLAIN stack (no PD_TASK_STACK_CAPS): this task is the only place that
	// touches flash for these keys -- see PsramTask.hpp. The blobs live in
	// namespace-scope statics, so the frame is only the drain loop plus
	// nvs_open/nvs_set_str/nvs_commit's own depth. 6144 B matches cdr_persist and
	// cdr_archive, the closest precedents; like theirs it is a reasoned figure
	// until stackHwm shows the real one.
	void nvsWriterTask(void*)
	{
		for (;;)
		{
			// A give that lands while a pass runs is not lost: the next take returns
			// at once and the pass looks at every key again.
			(void)ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
			PD_ASSERT_NOT_PSRAM_STACK();
			(void)stagerRef().drainOnce(nvsSink);
		}
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
	if (s_devices == nullptr || s_forwards == nullptr)
	{
		ESP_LOGE(kTag, "staging slot allocation failed -- device table and forwards will not persist");
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
			ESP_LOGE(kTag, "queue create failed -- device table and forwards will not persist");
			deleteQueues(t);
			freeSlots();
			started = false;
			return;
		}
	}
	TaskHandle_t handle = nullptr;
	if (xTaskCreatePinnedToCore(nvsWriterTask, "nvs_writer", 6144, nullptr, 1, &handle, 0) != pdPASS)
	{
		ESP_LOGE(kTag, "xTaskCreate nvs_writer failed -- device table and forwards will not persist");
		deleteQueues(t);
		freeSlots();
		started = false;
		return;
	}
	// Build the function-static now, not under _mutex on the first *72 (CdrRing's
	// boot-time reasoning). The task is parked in ulTaskNotifyTake until the first
	// stage() notifies it, which needs running == true, so it cannot reach this early.
	(void)stagerRef();
	writerHandle().store(handle, std::memory_order_release);
	running().store(true, std::memory_order_release);
#endif
}

StageResult stage(Key k, FunctionRef<void(BlobWriter&)> fill)
{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	if (!running().load(std::memory_order_acquire)) return StageResult::NotRunning;
#endif
	const StageResult r = stagerRef().stage(k, fill);
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	if (r == StageResult::Ok)
	{
		xTaskNotifyGive(writerHandle().load(std::memory_order_acquire));   // never blocks
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
