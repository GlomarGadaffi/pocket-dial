// CdrRing.cpp: the CDR ring buffer, extracted out of RequestsHandler.
#include "CdrRing.hpp"

#include <chrono>
#include <cstdlib>
#include <cstring>

#include "PbxPersist.hpp"

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "PsramTask.hpp"   // PD_ASSERT_NOT_PSRAM_STACK -- issue #277
#endif

namespace
{
	using pbxpersist::deserializeBlob;

	// NVS namespace holding the persisted CDR ring (distinct from
	// pbxpersist::kNvsNamespace — the CDR blob has its own key shape and is
	// unrelated to the PBX feature-config tables).
	constexpr auto NVS_CDR_NS = "cdrlog";

	// Same clock RequestsHandler::nowEpochMs() uses; duplicated here rather than
	// reached through an engine indirection, since it is stateless and this
	// class otherwise needs no engine service at all (see class comment).
	uint64_t nowEpochMs()
	{
		return static_cast<uint64_t>(
			std::chrono::duration_cast<std::chrono::milliseconds>(
				std::chrono::steady_clock::now().time_since_epoch()).count());
	}

	// Per-field raw-length cap for caller/callee before truncation. Mirrors
	// CdrArchive.cpp's kMaxAorRaw for the identical reason: anchor-sourced
	// values bypass isValidAor()'s length bound (see CallDetailRecord.hpp).
	constexpr size_t kMaxAorRaw = 48;

	// caller(48) + '\t' + callee(48) + '\t' + startMs(20 digits, uint64_t max)
	// + '\t' + durationSec(10 digits, uint32_t max) + '\t' + result(1 digit,
	// 0-4) + '\n' = 48+1+48+1+20+1+10+1+1+1 = 132, rounded up to 140 for
	// margin. CdrRingBlob::kCapacity (CdrRing.hpp) must track this constant;
	// the static_assert below fails the build, not just a test, if they drift.
	constexpr size_t kMaxLineBytes = 140;
	static_assert(CdrRingBlob::kCapacity == POCKETDIAL_CDR_RECORDS * kMaxLineBytes + 1,
		"CdrRingBlob::kCapacity must match kMaxLineBytes's arithmetic here");

	// Appends `raw` (truncated to `maxRaw` bytes) to buf[0..cap), starting at
	// *used, followed by `sep` if non-'\0'. Never writes past cap; if the
	// buffer would overflow, the append truncates silently rather than
	// corrupting adjacent memory (same discipline as CdrArchive.cpp's
	// appendCsvField) -- this can only trigger if kMaxLineBytes above is
	// wrong. No CSV-style quoting: this format is unchanged from before issue
	// #273's fix (plain tab/newline separated, no escaping), so
	// deserializeBlob() needs no matching change.
	void appendField(char* buf, size_t cap, size_t& used, std::string_view raw,
		size_t maxRaw, char sep)
	{
		if (raw.size() > maxRaw) raw = raw.substr(0, maxRaw);
		size_t n = raw.size();
		if (used + n > cap) n = (used < cap) ? (cap - used) : 0;
		if (n > 0)
		{
			std::memcpy(buf + used, raw.data(), n);
			used += n;
		}
		if (sep != '\0' && used < cap)
		{
			buf[used++] = sep;
		}
	}

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	// Queue depth 1 (issue #315): persist() already sends non-blocking
	// (xQueueSend(..., 0), see its comment) and already treats a dropped
	// blob as fine -- every blob is a COMPLETE ring snapshot, not one
	// incremental record, so a dropped blob's contents are entirely
	// superseded by whichever later blob the writer task does drain, and
	// persistence for that particular call is merely delayed until the
	// next one ends. Depth 2 bought one extra buffered blob before that
	// (already-accepted) degradation path kicks in; nothing reads queue
	// length or otherwise depends on 2 specifically. At depth 1, back-to-
	// back call teardowns arriving faster than one NVS write completes
	// start dropping one call sooner than they used to -- same kind of
	// delay the design already tolerates, not a new failure mode.
	constexpr size_t kQueueDepth = 1;

	QueueHandle_t& cdrPersistQueue()
	{
		static QueueHandle_t q = nullptr;
		return q;
	}

	void cdrPersistWriterTask(void*)
	{
		// `blob` is deliberately a function-STATIC, not a stack-local. At the
		// default POCKETDIAL_CDR_RECORDS=32, CdrRingBlob::kCapacity is 4481
		// bytes -- MORE than this task's entire 4096-byte stack, before
		// counting xQueueReceive()'s own frame or nvs_open/nvs_set_str/
		// nvs_commit's. A stack-local here would overflow on the very first
		// persist after boot, reintroducing this PR's own bug class inside
		// its own fix (caught in review -- sonnet-OG, thank you -- not on
		// hardware, where it would have looked like an unrelated new crash).
		// Static also decouples the writer task's required stack size from
		// POCKETDIAL_CDR_RECORDS, which CallDetailRecord.hpp documents as a
		// compile-time -D override: a numeric stack size chosen "with
		// margin" for today's default would silently become insufficient
		// again if that macro is ever raised, without touching this file to
		// notice. Safe without synchronization because this task is the
		// only reader/writer of `blob` and processes exactly one queue item
		// at a time on its own single thread of execution.
		static CdrRingBlob blob;
		while (true)
		{
			if (xQueueReceive(cdrPersistQueue(), &blob, portMAX_DELAY) == pdTRUE)
			{
				// Defense in depth (#277 suggestion 3): this task is created
				// WITHOUT PD_TASK_STACK_CAPS (plain xTaskCreatePinnedToCore
				// below), so this should never fire -- if it ever does,
				// someone changed the task creation call without reading
				// PsramTask.hpp first.
				PD_ASSERT_NOT_PSRAM_STACK();
				nvs_handle_t h;
				if (nvs_open(NVS_CDR_NS, NVS_READWRITE, &h) == ESP_OK)
				{
					nvs_set_str(h, "ring", blob.text);
					nvs_commit(h);
					nvs_close(h);
				}
			}
		}
	}

	// Idempotent. Called once from load() (already the class's single-
	// threaded, before-any-handler-dispatches boot hook -- see its doc
	// comment) rather than lazily from the first persist(): that would
	// otherwise make the very first call teardown pay for xQueueCreateWithCaps
	// AND xTaskCreatePinnedToCore, on the SIP thread or a PSRAM-stacked task, in
	// the middle of real-time work -- the same reasoning CdrArchive.cpp's
	// init() documents for forcing its own queue to construct at boot.
	void ensureWriterTaskStarted()
	{
		static bool started = false;
		if (started) return;
		started = true;
		// Issue #315 (follow-up to #319's depth reduction): the queue's OWN
		// storage (kQueueDepth * CdrRingBlob::kCapacity, ~4.5 KB at depth 1)
		// now lives in PSRAM instead of internal DRAM -- a different question
		// from #277's rule, and does not violate it. #277 forbids a task whose
		// STACK is in PSRAM from touching flash, because cache-disable during
		// the flash op makes PSRAM unreadable and the task cannot even
		// execute (its own stack is unreadable). This queue's storage is
		// data, not a stack, and xQueueReceive() below fully copies an item
		// OUT of that storage into `blob` -- a function-static that already
		// lives in internal RAM (see cdrPersistWriterTask's comment) -- before
		// this task does anything flash-related. By the time nvs_set_str()
		// disables the cache, the PSRAM-backed queue storage has not been
		// touched since the copy completed and is not touched again until the
		// NEXT xQueueReceive(), well after cache is re-enabled. Net effect:
		// this queue's fixed, never-freed cost against internal DRAM -- #315's
		// original 9046 B, or #319's already-halved ~4.5 KB -- is now ~0.
		// Must be paired with vQueueDeleteWithCaps(), not vQueueDelete() --
		// see below.
		cdrPersistQueue() = xQueueCreateWithCaps(kQueueDepth, sizeof(CdrRingBlob), MALLOC_CAP_SPIRAM);
		if (cdrPersistQueue() == nullptr)
		{
			ESP_LOGE("CdrRing", "xQueueCreateWithCaps failed -- CDR ring will not persist across reboot");
			started = false;   // allow a retry on a later load() (there is none today, but cheap to allow)
			return;
		}
		// PLAIN stack (no PD_TASK_STACK_CAPS): this task is the only place
		// allowed to touch flash for the CDR ring -- see PsramTask.hpp.
		// 6144 bytes matches CdrArchive.cpp's own writer task, the closest
		// precedent (a comparable flash-adjacent worker with a blocking
		// library call chain) -- and, like that one, this is a reasoned
		// estimate, NOT measured with uxTaskGetStackHighWaterMark() on real
		// hardware. `blob` itself is static now (see cdrPersistWriterTask's
		// comment), so this only needs to cover xQueueReceive()'s frame and
		// nvs_open/nvs_set_str/nvs_commit's internal depth. Flag for
		// hardware bring-up, same as CdrArchive.cpp's.
		if (xTaskCreatePinnedToCore(cdrPersistWriterTask, "cdr_persist", 6144,
			nullptr, 1, nullptr, 0) != pdPASS)
		{
			ESP_LOGE("CdrRing", "xTaskCreate cdr_persist failed -- CDR ring will not persist across reboot");
			// Issue #315: created with xQueueCreateWithCaps() above, so it must
			// be torn down with the matching vQueueDeleteWithCaps(), not
			// vQueueDelete() -- the plain form does not know how to free
			// PSRAM-backed queue storage.
			vQueueDeleteWithCaps(cdrPersistQueue());
			cdrPersistQueue() = nullptr;
			started = false;
		}
	}
#endif
}

void CdrRing::serializeForPersist(
	const std::array<CallDetailRecord, POCKETDIAL_CDR_RECORDS>& ring,
	size_t head, size_t count, CdrRingBlob& out)
{
	// Reset first: `out` may be a reused static (see persist()'s and
	// cdrPersistWriterTask's callers) carrying a longer previous blob, and
	// std::memset is the only way to guarantee every trailing byte is '\0'
	// again -- a shorter new blob must not leave stale bytes from the last
	// call sitting after its own NUL terminator.
	std::memset(out.text, 0, sizeof(out.text));
	size_t used = 0;
	const size_t cap = sizeof(out.text) - 1;   // reserve the last byte as a hard NUL
	for (size_t i = 0; i < count; ++i)
	{
		size_t idx = (head + POCKETDIAL_CDR_RECORDS - count + i) % POCKETDIAL_CDR_RECORDS;
		const CallDetailRecord& r = ring[idx];
		appendField(out.text, cap, used, r.caller, kMaxAorRaw, '\t');
		appendField(out.text, cap, used, r.callee, kMaxAorRaw, '\t');
		appendField(out.text, cap, used, std::to_string(r.startMs), 20, '\t');
		appendField(out.text, cap, used, std::to_string(r.durationSec), 10, '\t');
		appendField(out.text, cap, used, std::to_string(static_cast<int>(r.result)), 1, '\n');
	}
}

const CallDetailRecord& CdrRing::record(const std::shared_ptr<Session>& session,
	std::string_view srcNumber, std::string_view destNumber)
{
	CallDetailRecord rec;
	rec.caller = std::string(srcNumber);
	rec.callee = std::string(destNumber);

	uint64_t startMs = nowEpochMs();
	uint32_t durationSec = 0;
	CdrResult result = CdrResult::Failed;

	if (session)
	{
		auto now = std::chrono::steady_clock::now();
		startMs = static_cast<uint64_t>(
			std::chrono::duration_cast<std::chrono::milliseconds>(
				session->getStartTime().time_since_epoch()).count());

		switch (session->getState())
		{
			// Both Connected and Bye are "answered": a normal call ends via BYE, which
			// sets the state to Bye (NOT Connected) just before endCall() runs, while
			// the echo (777) path tears down straight from Connected. Session::setState
			// resets _startTime to the connect instant on the Connected transition and
			// the later Bye transition does NOT touch it, so getStartTime() still marks
			// the answer instant in both cases — talk time is now - startTime.
			case Session::State::Connected:
			case Session::State::Held:   // call torn down mid-hold → still Answered (#73)
			case Session::State::Bye:
				result = CdrResult::Answered;
				{
					int64_t secs = static_cast<int64_t>(
						std::chrono::duration_cast<std::chrono::seconds>(
							now - session->getStartTime()).count());
					if (secs < 0) secs = 0;
					durationSec = static_cast<uint32_t>(secs);
				}
				break;
			case Session::State::Busy:        result = CdrResult::Busy;        break;
			case Session::State::Cancel:      result = CdrResult::Cancelled;   break;
			case Session::State::Unavailable: result = CdrResult::Unavailable; break;
			default:                          result = CdrResult::Failed;      break;
		}
	}

	rec.startMs = startMs;
	rec.durationSec = durationSec;
	rec.result = result;

	// Fixed ring write: overwrite the oldest slot once full (no heap growth).
	const size_t writtenIdx = _head;
	_ring[writtenIdx] = std::move(rec);
	_head = (_head + 1) % POCKETDIAL_CDR_RECORDS;
	if (_count < POCKETDIAL_CDR_RECORDS)
	{
		++_count;
	}

	// Persist the ring so records survive reboot (write-through on teardown; no-op
	// on host). Caller (RequestsHandler::endCall) holds _mutex. See persist()
	// for the wear note.
	persist();

	return _ring[writtenIdx];
}

std::vector<CallDetailRecord> CdrRing::snapshot() const
{
	std::vector<CallDetailRecord> out;
	out.reserve(_count);
	for (size_t i = 0; i < _count; ++i)
	{
		// _head points one past the newest; walk backwards with wrap.
		size_t idx = (_head + POCKETDIAL_CDR_RECORDS - 1 - i) % POCKETDIAL_CDR_RECORDS;
		out.push_back(_ring[idx]);
	}
	return out;
}

std::string CdrRing::lastCallerFor(std::string_view calleeExt) const
{
	for (size_t i = 0; i < _count; ++i)
	{
		size_t idx = (_head + POCKETDIAL_CDR_RECORDS - 1 - i) % POCKETDIAL_CDR_RECORDS;
		if (_ring[idx].callee == calleeExt && !_ring[idx].caller.empty())
		{
			return _ring[idx].caller;
		}
	}
	return std::string();
}

void CdrRing::load()
{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	// Issue #273/#288: start the dedicated persist writer task now, at boot,
	// before any handler is dispatching -- not lazily inside persist() (see
	// ensureWriterTaskStarted()'s doc comment for why).
	ensureWriterTaskStarted();

	nvs_handle_t h;
	if (nvs_open(NVS_CDR_NS, NVS_READWRITE, &h) != ESP_OK)
	{
		return;
	}
	size_t len = 0;
	if (nvs_get_str(h, "ring", nullptr, &len) == ESP_OK && len > 0)
	{
		std::string buf(len, '\0');
		if (nvs_get_str(h, "ring", buf.data(), &len) == ESP_OK)
		{
			if (!buf.empty() && buf.back() == '\0') buf.pop_back();
			// Record: caller \t callee \t startMs \t durationSec \t result(int)
			for (const auto& rec : deserializeBlob(buf))
			{
				if (rec.size() < 5) continue;
				if (_count >= POCKETDIAL_CDR_RECORDS) break;
				CallDetailRecord r;
				r.caller = rec[0];
				r.callee = rec[1];
				r.startMs = static_cast<uint64_t>(strtoull(rec[2].c_str(), nullptr, 10));
				r.durationSec = static_cast<uint32_t>(strtoul(rec[3].c_str(), nullptr, 10));
				int ri = atoi(rec[4].c_str());
				r.result = (ri >= 0 && ri <= static_cast<int>(CdrResult::Failed))
					? static_cast<CdrResult>(ri) : CdrResult::Failed;
				// Records were serialized oldest-first; append preserving order.
				_ring[_head] = std::move(r);
				_head = (_head + 1) % POCKETDIAL_CDR_RECORDS;
				++_count;
			}
		}
	}
	nvs_close(h);
#endif
}

void CdrRing::clearAll()
{
	_ring = {};
	_head = 0;
	_count = 0;
	persist();
}

void CdrRing::persist()
{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	// Issue #273/#288: this used to call nvs_set_str/nvs_commit directly
	// here, on whatever task called endCall() -- including tel_wsw and the
	// makecall worker, both PD_TASK_STACK_CAPS (PSRAM-stacked) tasks. A flash
	// write disables the flash cache, which makes PSRAM unreadable, which
	// crashes a task whose own stack lives there
	// (esp_task_stack_is_sane_cache_disabled()). See PsramTask.hpp's
	// corrected comment for the full story.
	//
	// serializeForPersist() is pure CPU work (string formatting into a fixed
	// buffer, no allocation) -- safe on any stack, including a PSRAM one.
	// The actual flash write now happens ONLY on cdr_persist_writer's plain
	// stack; this function just builds the blob and hands it off.
	//
	// `blob` is a function-static, not a stack-local, for the same reason
	// cdrPersistWriterTask's is (see that function's comment): at
	// CdrRingBlob::kCapacity ~4.5 KB, a stack-local here would add real
	// pressure to whichever task calls persist() -- tel_wsw and the
	// makecall worker (both 12 KB PSRAM stacks) or the SIP thread (8 KB) --
	// on the exact tasks issue #273 spent a night finding are tight under
	// load. Safe without synchronization: every call to persist() (via
	// record()/clearAll()) already runs under RequestsHandler::_mutex (see
	// this class's own locking convention), which already serializes every
	// caller to exactly one at a time -- the same property that makes the
	// static safe, just enforced by the engine's lock instead of by this
	// function running on a single dedicated task.
	static CdrRingBlob blob;
	serializeForPersist(_ring, _head, _count, blob);

	// Non-blocking: never stall the caller (which may be holding
	// RequestsHandler::_mutex, or be a real-time task) waiting for queue
	// space. Dropping is safe here in a way it would not be for
	// CdrArchive.cpp's per-row queue: every blob is a COMPLETE snapshot of
	// the whole ring, not one incremental record, so a dropped blob's
	// contents are entirely superseded by whichever later blob the writer
	// task does end up draining -- nothing is permanently lost, persistence
	// for THIS particular call is merely delayed until the next one ends.
	//
	// Guard the handle (same convention TelephonyAnchorClient.cpp's
	// _wsWorkQueue uses): xQueueSend on a null handle is a FreeRTOS
	// configASSERT, not a safe no-op, and ensureWriterTaskStarted() can leave
	// the queue null if xQueueCreateWithCaps/xTaskCreatePinnedToCore failed under
	// memory pressure -- exactly the condition #273 was investigating, so
	// this path degrading to "CDR not persisted this call" instead of a
	// second crash matters more here than almost anywhere else in the tree.
	if (cdrPersistQueue() != nullptr)
	{
		xQueueSend(cdrPersistQueue(), &blob, 0);
	}
#endif
}
