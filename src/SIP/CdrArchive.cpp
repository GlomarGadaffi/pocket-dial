// CdrArchive.cpp -- see CdrArchive.hpp for the full design rationale.
#include "CdrArchive.hpp"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <mutex>

#include "TimeSync.hpp"

#if defined(PD_ETH_HAS_SD)
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <cerrno>
#include <dirent.h>
#include <sys/stat.h>

// Defined in main/esp_main_eth.cpp, which owns the card -- same declare-
// rather-than-include pattern HttpServer.cpp uses for the same symbol (that
// file is a transport main, not a module).
extern "C" bool pd_sd_mounted(void);
#endif

namespace cdrarchive
{

namespace
{
	// Per-field raw-length caps applied BEFORE escaping, chosen so the escaped
	// worst case (every raw byte a '"', each doubled, both wrapping quotes
	// added) still fits QueuedLine::line with room to spare:
	//   timestamp(20) + ',' + callId(2*64+2=130) + ',' + caller(2*48+2=98) +
	//   ',' + callee(98) + ',' + duration(10) + ',' + result(11) + ',' +
	//   reason(2*48+2=98) + 6 commas = 20+130+98+98+10+11+98+6 = 471,
	// against a 600-byte buffer.
	constexpr size_t kMaxCallIdRaw = 64;
	constexpr size_t kMaxAorRaw    = 48;  // caller/callee -- see CallDetailRecord.hpp's
	                                      // updated comment: anchor-sourced values
	                                      // bypass isValidAor()'s length bound, so
	                                      // this module enforces its own.
	constexpr size_t kMaxReasonRaw = 48;

	// Appends one RFC 4180 field to `buf` (which must already hold `used`
	// bytes of prior content) followed by `sep` (a field separator, or '\0'
	// for the last field -- appended only if non-'\0'). `raw` is truncated to
	// `maxRaw` bytes first. The field is quoted iff (after truncation) it
	// contains a comma, quote, CR or LF; embedded quotes are doubled. Never
	// writes past `cap`; if the buffer would overflow, the append is silently
	// truncated (the row still ends up NUL-terminated and syntactically valid
	// CSV, just short) rather than corrupting adjacent memory -- this can only
	// happen if the per-field caps above are wrong, and the fixed sizing
	// above is exactly what a debug assertion would otherwise be checking.
	void appendCsvField(char* buf, size_t cap, size_t& used, std::string_view raw,
		size_t maxRaw, char sep)
	{
		if (raw.size() > maxRaw) raw = raw.substr(0, maxRaw);

		bool needsQuote = false;
		for (char c : raw)
		{
			if (c == ',' || c == '"' || c == '\r' || c == '\n') { needsQuote = true; break; }
		}

		auto putc_ = [&](char c) {
			if (used + 1 < cap) buf[used++] = c;  // always keep 1 byte for the final NUL
		};

		if (needsQuote) putc_('"');
		for (char c : raw)
		{
			if (c == '"') putc_('"');  // double it
			putc_(c);
		}
		if (needsQuote) putc_('"');
		if (sep != '\0') putc_(sep);
		buf[used < cap ? used : cap - 1] = '\0';
	}
}  // namespace

const char* csvHeader()
{
	return "timestamp,call_id,caller,callee,duration_sec,result,reason";
}

bool formatLine(const CallDetailRecord& rec, std::string_view callId,
	std::string_view reason, uint64_t nowEpochSeconds, uint64_t nowSteadyMs,
	QueuedLine& out)
{
	out = QueuedLine{};

	if (nowEpochSeconds == 0) return false;  // never synced -- see header comment

	// Derive the call's START in wall-clock terms: how long ago (in steady-
	// clock terms) did it start, subtracted from "now" in wall-clock terms.
	// Clamped both directions against clock-skew/ordering surprises (a
	// slightly-stale nowSteadyMs snapshot racing rec.startMs, or a nonsensical
	// delta bigger than the wall clock has even been running) rather than
	// underflowing into a bogus large epoch value.
	int64_t deltaMs = static_cast<int64_t>(nowSteadyMs) - static_cast<int64_t>(rec.startMs);
	if (deltaMs < 0) deltaMs = 0;
	uint64_t deltaSec = static_cast<uint64_t>(deltaMs) / 1000;
	uint64_t startEpochSec = (deltaSec < nowEpochSeconds) ? (nowEpochSeconds - deltaSec) : nowEpochSeconds;

	char ts[32];
	const size_t tsLen = timesync::formatRfc3339(static_cast<time_t>(startEpochSec), ts, sizeof(ts));
	if (tsLen == 0) return false;  // shouldn't happen given cap above, but never emit a half-row

	// Date component for the filename: the first 10 bytes of the RFC 3339
	// timestamp are exactly "YYYY-MM-DD" by construction (formatRfc3339 always
	// emits that prefix before 'T').
	std::memcpy(out.date, ts, 10);
	out.date[10] = '\0';

	size_t used = 0;
	appendCsvField(out.line, sizeof(out.line), used, std::string_view(ts, tsLen), tsLen, ',');
	appendCsvField(out.line, sizeof(out.line), used, callId, kMaxCallIdRaw, ',');
	appendCsvField(out.line, sizeof(out.line), used, rec.caller, kMaxAorRaw, ',');
	appendCsvField(out.line, sizeof(out.line), used, rec.callee, kMaxAorRaw, ',');

	char durBuf[16];
	int durLen = std::snprintf(durBuf, sizeof(durBuf), "%u", static_cast<unsigned>(rec.durationSec));
	appendCsvField(out.line, sizeof(out.line), used,
		std::string_view(durBuf, durLen > 0 ? static_cast<size_t>(durLen) : 0), sizeof(durBuf), ',');

	const char* resultStr = cdrResultToString(rec.result);
	appendCsvField(out.line, sizeof(out.line), used, resultStr, std::strlen(resultStr), ',');

	appendCsvField(out.line, sizeof(out.line), used, reason, kMaxReasonRaw, '\0');

	return true;
}

// ── WriterQueue ──────────────────────────────────────────────────────────────

WriterQueue::WriterQueue(size_t capacity) : _buf(capacity) {}

bool WriterQueue::push(const QueuedLine& line)
{
	std::lock_guard<std::mutex> lock(_m);
	if (_buf.empty() || _count >= _buf.size()) return false;  // full (or zero-capacity) -- drop
	const size_t tail = (_head + _count) % _buf.size();
	_buf[tail] = line;
	++_count;
	return true;
}

bool WriterQueue::pop(QueuedLine& out)
{
	std::lock_guard<std::mutex> lock(_m);
	if (_count == 0) return false;
	out = _buf[_head];
	_head = (_head + 1) % (_buf.empty() ? 1 : _buf.size());
	--_count;
	return true;
}

size_t WriterQueue::size() const
{
	std::lock_guard<std::mutex> lock(_m);
	return _count;
}

void WriterQueue::clear()
{
	std::lock_guard<std::mutex> lock(_m);
	_head = 0;
	_count = 0;
}

void drainAll(WriterQueue& queue, Sink& sink)
{
	QueuedLine line;
	while (queue.pop(line))
	{
		sink.append(line);
	}
}

// ── Production singleton ────────────────────────────────────────────────────

namespace
{
	// Queue depth: mirrors CdrRing's own POCKETDIAL_CDR_RECORDS default (32) --
	// there is no reason the archive needs to outrun how many calls can even
	// be in flight/recently-ended, and a bounded queue is the whole point of
	// "drop rather than block" under load.
	constexpr size_t kQueueDepth = 32;

	WriterQueue& queue()
	{
		static WriterQueue q(kQueueDepth);
		return q;
	}

	// Guards the g_sink pointer itself (not what it points to) against a
	// concurrent setSinkForTest() -- production code only ever sets this once,
	// from init(); the mutex exists for test-suite hygiene, not a real runtime
	// race.
	std::mutex& sinkMutex()
	{
		static std::mutex m;
		return m;
	}

	// Makes "drain everything currently queued" (writer task) and "clear the
	// queue, then wipe the sink" (wipeAll(), HTTP task) mutually exclusive as
	// whole operations. WriterQueue's own internal mutex only protects each
	// individual push/pop/clear/size call -- it does NOT span the writer
	// loop's pop-then-append pair, so without this, wipeAll() can run its
	// clear()+wipe() in the gap between a drainAll() pop() and the matching
	// sink.append(), and the writer resumes and appends a pre-reset line into
	// the brand-new post-wipe file. This lock closes exactly that window: the
	// writer either finishes draining everything pending BEFORE a wipe can
	// start, or the wipe finishes its clear+wipe BEFORE the writer can drain
	// anything new. Not held by the free drainAll(WriterQueue&, Sink&)
	// function itself (host tests call that directly with no concurrent
	// wipeAll() to race) -- only by the production call sites below.
	std::mutex& drainWipeMutex()
	{
		static std::mutex m;
		return m;
	}

	Sink*& sinkSlot()
	{
		static Sink* s = nullptr;
		return s;
	}
}  // namespace

Sink* setSinkForTest(Sink* sink)
{
	std::lock_guard<std::mutex> lock(sinkMutex());
	Sink* prev = sinkSlot();
	sinkSlot() = sink;
	return prev;
}

size_t pendingForTest()
{
	return queue().size();
}

void record(const CallDetailRecord& rec, std::string_view callId, std::string_view reason)
{
	Sink* sink;
	{
		std::lock_guard<std::mutex> lock(sinkMutex());
		sink = sinkSlot();
	}
	if (sink == nullptr) return;  // no archive installed on this build/boot -- see header

	const uint64_t nowEpoch = timesync::epochSeconds();
	if (nowEpoch == 0) return;    // never synced -- drop rather than mis-date (see header)

	const uint64_t nowSteadyMs = static_cast<uint64_t>(
		std::chrono::duration_cast<std::chrono::milliseconds>(
			std::chrono::steady_clock::now().time_since_epoch()).count());

	QueuedLine line;
	if (!formatLine(rec, callId, reason, nowEpoch, nowSteadyMs, line)) return;

	queue().push(line);  // non-blocking; silently dropped if the queue is full
}

void wipeAll()
{
	// Check the sink FIRST, same order as record() -- queue() is a
	// function-local static that only ever gets constructed by init() on the
	// PD_ETH_HAS_SD path (which force-constructs it up front specifically to
	// avoid a lazy runtime allocation, see init()'s comment). On every other
	// build no Sink is ever installed, so returning here means queue() is
	// NEVER called and the ~19.5 KB WriterQueue backing vector never gets
	// lazily constructed on the HTTP task at factory-reset time -- which is
	// exactly what used to happen when this function touched queue() first.
	Sink* sink;
	{
		std::lock_guard<std::mutex> lock(sinkMutex());
		sink = sinkSlot();
	}
	if (sink == nullptr) return;  // no archive installed on this build/boot

	// Mutually exclude against the writer task's drain loop for the whole
	// clear+wipe operation -- see drainWipeMutex()'s doc comment for why a
	// per-call lock on WriterQueue alone isn't enough.
	std::lock_guard<std::mutex> lock(drainWipeMutex());

	// Drop anything still queued FIRST -- a factory reset must not let a
	// pre-reset call get written out by the writer task after the wipe below
	// has already run (see WriterQueue::clear()'s doc comment).
	queue().clear();
	sink->wipe();
}

#if defined(PD_ETH_HAS_SD)

namespace
{
	constexpr const char* kArchiveDir = "/sdcard/cdr";

	class FatFsSink final : public Sink
	{
	public:
		void append(const QueuedLine& line) override
		{
			std::lock_guard<std::mutex> lock(_ioMutex);

			char path[64];
			std::snprintf(path, sizeof(path), "%s/%s.csv", kArchiveDir, line.date);

			// stat() first (not ftell-after-open): a file that exists but is
			// empty gets no header rewritten into it every append, and a file
			// that doesn't exist yet gets exactly one.
			struct stat st{};
			const bool isNew = (::stat(path, &st) != 0);

			std::FILE* f = std::fopen(path, "a");
			if (f == nullptr) return;  // best-effort: card may have been pulled mid-run

			if (isNew)
			{
				std::fputs(csvHeader(), f);
				std::fputc('\n', f);
			}
			std::fputs(line.line, f);
			std::fputc('\n', f);
			std::fclose(f);
		}

		void wipe() override
		{
			std::lock_guard<std::mutex> lock(_ioMutex);

			DIR* d = ::opendir(kArchiveDir);
			if (d == nullptr) return;  // nothing to wipe (directory never created)

			struct dirent* ent;
			while ((ent = ::readdir(d)) != nullptr)
			{
				if (ent->d_name[0] == '.') continue;  // skip "." / ".."
				char path[80];
				std::snprintf(path, sizeof(path), "%s/%s", kArchiveDir, ent->d_name);
				std::remove(path);
			}
			::closedir(d);
		}

	private:
		// Serializes append() (writer task) against wipe() (HTTP task, via
		// factory reset) on this one Sink instance -- see CdrArchive.hpp's
		// SD-write-discipline note. Never held across anything that blocks
		// beyond the file op itself.
		std::mutex _ioMutex;
	};

	FatFsSink& fatFsSink()
	{
		static FatFsSink s;
		return s;
	}

	void writerTaskBody(void*)
	{
		for (;;)
		{
			{
				// See drainWipeMutex()'s doc comment: this makes "drain
				// everything currently queued" one atomic operation relative
				// to wipeAll()'s clear+wipe, closing the factory-reset TOCTOU
				// window where a popped-but-not-yet-appended line could
				// survive a wipe into the fresh post-reset file.
				std::lock_guard<std::mutex> lock(drainWipeMutex());
				drainAll(queue(), fatFsSink());
			}
			vTaskDelay(pdMS_TO_TICKS(200));
		}
	}
}  // namespace

void init()
{
	static bool started = false;
	if (started) return;  // idempotent -- see doc comment
	started = true;

	if (!pd_sd_mounted()) return;  // gate on pd_sd_mounted(): no card, stay a no-op forever

	// mkdir() failing with EEXIST is the expected steady state after the
	// first boot; anything else just means append() below will keep failing
	// its own fopen(), which is already handled as best-effort there.
	if (::mkdir(kArchiveDir, 0775) != 0 && errno != EEXIST)
	{
		return;
	}

	{
		std::lock_guard<std::mutex> lock(sinkMutex());
		sinkSlot() = &fatFsSink();
	}

	// Force queue()'s function-local static to construct HERE, on whatever
	// task calls init() (app_main, before the SIP/HTTP tasks are spawned),
	// rather than lazily on first use -- which would otherwise be the SIP
	// thread's first endCall() (record() -> queue()) or the writer task
	// below, both real-time-ish contexts. The vector backing it (32 *
	// sizeof(QueuedLine), ~19.5 KB) is heap-allocated exactly ONCE, here, and
	// never again -- consistent with "no malloc/new in RTOS tasks after
	// init".
	(void)queue();

	xTaskCreatePinnedToCore(writerTaskBody, "cdr_archive", 6144, nullptr, 1, nullptr, 0);
	// Stack size is a reasoned estimate (FatFs + snprintf need more headroom
	// than LogQueue's 3072-byte drain task, see esp_main_eth.cpp), NOT
	// measured with uxTaskGetStackHighWaterMark() -- this task has never run
	// on real hardware. Flag for hardware bring-up: check high-water mark on
	// first bench test and revise if it's tight.
}

#else  // !PD_ETH_HAS_SD -- every other build (host, wifi, lan8720, eth/waveshare)

void init()
{
	// No-op by construction: no Sink is ever installed, so record()/wipeAll()
	// above stay harmless no-ops too. This is "degrade silently to today's
	// behaviour" for every build without the Elite's SD slot.
}

#endif  // PD_ETH_HAS_SD

}  // namespace cdrarchive
