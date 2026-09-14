#ifndef CDR_ARCHIVE_HPP
#define CDR_ARCHIVE_HPP

// CdrArchive — issue #194 Stage 1: append-only SD-card CDR archive.
//
// WHAT THIS IS. CdrRing (CdrRing.hpp) is a 32-slot NVS-backed ring for the live
// dashboard Call Log — bounded, fast, and unconditionally present. This module is
// a SEPARATE, unbounded-duration ARCHIVE of the same events, written to
// `/sdcard/cdr/YYYY-MM-DD.csv`, one file per day, append-only. CdrRing is
// UNTOUCHED by this work: same fields, same NVS format, same dashboard view --
// "SD is the archive, not a replacement" (issue #194 Stage 1 scope).
//
// WHY A SEPARATE MODULE INSTEAD OF EXTENDING CdrRing/CallDetailRecord. The epic
// also flags that CallDetailRecord's 5 fields (no Call-ID, disposition reason,
// ...) are thin for an archive. Growing CallDetailRecord itself was deliberately
// NOT done here: it is the ring's fixed-footprint slot type, its NVS blob shape,
// and (via CdrRing::snapshot()) the dashboard JSON's data model all at once --
// touching it risks exactly the "keep the ring exactly as-is" line this stage
// draws. Instead, endCall() (RequestsHandler.cpp) hands this module the two
// pieces of context it already has locally and previously discarded -- the
// Call-ID and the disposition `reason` string -- ALONGSIDE the CallDetailRecord
// CdrRing::record() just wrote (reusing its already-derived startMs/duration/
// result rather than re-deriving them). Direction, trunk/DID attribution and
// codec (also named in the epic) are NOT included: nothing on the call path
// available at endCall() cheaply carries them today (Session has no trunk/DID/
// codec field), and threading them through would touch call-routing code well
// beyond this stage's "minimal hook into endCall()" boundary -- filed as
// issue #221 rather than attempted here.
//
// SD WRITE DISCIPLINE (issue #194 prereq 1b, non-negotiable). `sdspi`'s
// poll_busy() is a hard busy-spin and routine card GC stalls 100-250 ms --
// longer than this firmware's audio jitter buffers tolerate, and endCall() runs
// on the SIP receive thread HOLDING RequestsHandler::_mutex. So record() below
// must never touch a file. It formats a fixed-size line (no heap) and pushes it
// into a small in-process queue; a dedicated low-priority FreeRTOS task (spawned
// by init(), ESP+PD_ETH_HAS_SD only) drains that queue and does the actual
// fopen/fwrite/fclose, off the SIP thread and outside _mutex entirely.
//
// WALL CLOCK. Every row needs a real, reboot-stable timestamp, which means this
// depends on timesync:: (TimeSync.hpp) having synced at least once. SNTP
// bring-up already exists in this tree (main/esp_main_eth.cpp calls
// timesync::start() from the Ethernet GOT_IP handler; landed on this branch
// before this stage was implemented -- see the PR description) so it is a
// dependency, not new work here. Until the first sync, record() silently
// DROPS the call rather than archiving it under a fabricated date -- an
// archive row with a wrong date is worse than a missing one, because nothing
// downstream can tell the two apart. This only affects calls that end in the
// (usually sub-second) window between boot and first SNTP reply; the NVS ring
// still has them, just without a reboot-stable timestamp, exactly as today.
//
// PLATFORM SHAPE (mirrors TimeSync.hpp/LogQueue.hpp's convention). The line
// FORMATTER (formatLine) and the QUEUE/DRAIN mechanics (WriterQueue, drainAll)
// are pure C++17 -- no FreeRTOS, no filesystem -- and fully host-unit-tested
// (CdrArchive_test.cpp). Only the production Sink (real fopen/mkdir/opendir
// against /sdcard/cdr) and the writer task are ESP-only, and further gated on
// PD_ETH_HAS_SD specifically -- NOT plain ESP_PLATFORM -- because the WiFi and
// LAN8720 transports build for boards with no SD slot at all and do not even
// declare `pd_sd_mounted()`; referencing it under a bare ESP_PLATFORM guard
// would be a link error on those transports that this host build can't catch.
// Every other build (host, wifi, lan8720, or eth/waveshare with no card wired)
// degrades silently: record()/wipeAll() become safe no-ops because no Sink is
// ever installed, exactly "today's behaviour" per the issue's Stage 1 scope.

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

#include "CallDetailRecord.hpp"

namespace cdrarchive
{

// One pre-formatted, pre-escaped, ready-to-append archive row. Fixed size and
// NUL-terminated so nothing on the enqueue side (the SIP thread, via record())
// ever allocates -- see the embedded-firmware "no malloc/new in RTOS tasks
// after init" rule this module is written to satisfy.
struct QueuedLine
{
	// "YYYY-MM-DD\0" -- also the file this line belongs in. date[0] == '\0'
	// marks an empty/invalid slot (WriterQueue never hands one of these out of
	// pop(), but zero-initialization must be a safe, inert value on its own).
	char date[11] = {};
	// One CSV row (no header, no trailing newline), RFC 4180 field-escaped
	// where a field's charset isn't already known-safe. 600 bytes covers the
	// mathematically worst case CdrArchive.cpp's per-field raw-length caps
	// allow (every field maximally quote-heavy, fully doubled, all four
	// escaped fields at their cap) with room to spare -- see formatLine()'s
	// implementation for the exact arithmetic.
	char line[600] = {};
};

// The CSV header row a fresh daily file gets before its first data row.
const char* csvHeader();

// Pure, host-testable, never allocates. Builds one CSV row from a CDR record
// (as CdrRing::record() returns it -- unchanged, un-re-derived) plus the two
// pieces of context only endCall() has: the dialog's Call-ID and its
// disposition `reason` (may be empty). `nowEpochSeconds`/`nowSteadyMs` let the
// caller supply "now" explicitly (production: timesync::epochSeconds() /
// std::chrono::steady_clock -- see record() below) so this function itself
// never reads a clock, which is what makes it deterministic to unit-test.
//
// The archived timestamp is the call's START (nowEpochSeconds minus how long
// ago rec.startMs -- a steady-clock reading -- was relative to nowSteadyMs),
// not the moment it was archived, matching what every other CDR field format
// means by "when" a call happened.
//
// Returns false (out left default-constructed / empty) when nowEpochSeconds
// is 0 -- the "clock never synced" sentinel timesync::epochSeconds() defines
// -- since there is no honest date to file the row under.
bool formatLine(const CallDetailRecord& rec, std::string_view callId,
	std::string_view reason, uint64_t nowEpochSeconds, uint64_t nowSteadyMs,
	QueuedLine& out);

// ── Sink: what actually persists a formatted line ───────────────────────────
// Production implementation (CdrArchive.cpp, PD_ETH_HAS_SD only) appends to
// /sdcard/cdr/<date>.csv and deletes that whole directory on wipe(). Tests
// substitute a FakeSink (CdrArchive_test.cpp) that just records calls, so the
// queue/drain/format pipeline is exercised with zero real file I/O.
class Sink
{
public:
	virtual ~Sink() = default;
	virtual void append(const QueuedLine& line) = 0;
	virtual void wipe() = 0;
};

// ── WriterQueue: the enqueue/dequeue mechanics, decoupled from FreeRTOS ─────
// A small fixed-capacity ring of QueuedLine. push() is what record() calls
// from the SIP thread: O(1), never allocates, drops (returns false) rather
// than blocks when full -- the same non-blocking-under-load contract
// LogQueue.hpp's xQueueSend(..., timeout=0) documents, expressed in portable
// C++ so it is host-testable and so the ESP build can wrap it in a real
// FreeRTOS task without duplicating the drop-on-full logic.
//
// THREAD SAFETY. On the production build this ONE instance (see queue() in
// CdrArchive.cpp) is touched from three different tasks -- the SIP thread
// (record() -> push), the writer task (drainAll() -> pop, in a loop), and the
// HTTP task (wipeAll() -> clear) -- so every method takes an internal mutex.
// This is a LEAF lock: nothing under it ever blocks (no I/O, no allocation
// after construction, no other lock acquired), so it is safe to take from
// inside RequestsHandler::_mutex (as record() does, via endCall()) as long as
// the reverse never happens -- nothing in this class calls back into
// RequestsHandler. Cheap enough (array index + memcpy of one QueuedLine)
// that contention is a non-issue at CDR-teardown rates.
class WriterQueue
{
public:
	explicit WriterQueue(size_t capacity);

	bool push(const QueuedLine& line);
	bool pop(QueuedLine& out);
	size_t size() const;
	// Discards everything currently queued without draining it to a sink.
	// Used by wipeAll(): a factory reset must not let a still-queued
	// pre-reset call get written out after the wipe completes.
	void clear();

private:
	mutable std::mutex _m;
	std::vector<QueuedLine> _buf;
	size_t _head = 0;
	size_t _count = 0;
};

// Drains everything currently in `queue` to `sink`, in FIFO order. This is the
// entire body of the ESP writer task's loop (see CdrArchive.cpp) and what
// CdrArchive_test.cpp calls directly against a FakeSink -- the "queue +
// writer-task decoupling logic" the issue asks to be host-testable.
void drainAll(WriterQueue& queue, Sink& sink);

// ── Production singleton entry points ───────────────────────────────────────

// Idempotent. ESP + PD_ETH_HAS_SD only: if pd_sd_mounted() is true, creates
// /sdcard/cdr, installs the production Sink and spawns the low-priority
// writer task. Every other build/condition: no-op (no Sink is ever
// installed, so record()/wipeAll() below stay harmless no-ops too). Call once
// from app_main(), after sd_mount().
void init();

// Non-blocking; safe to call from the SIP thread while holding
// RequestsHandler::_mutex (see endCall()). No-op when no Sink is installed
// (no card, non-eth-SD build, or init() not yet called) or the wall clock has
// never synced (see formatLine()'s doc comment).
void record(const CallDetailRecord& rec, std::string_view callId, std::string_view reason);

// Synchronous directory wipe. NOT SIP-thread-safe by the rules above --
// deletes files, so call it only from a non-realtime context that does not
// hold _mutex (HttpServer::sendApiFactoryReset, on the HTTP task, same as
// its existing MoH-upload fopen()). No-op when no Sink is installed. Also
// clears anything still queued so a pending pre-reset line can't be written
// out after the wipe.
void wipeAll();

// Test-only seam: installs `sink` as the active Sink (nullptr restores the
// "no Sink installed" no-op state) and returns whatever was active before,
// so a test can restore it afterwards. NOT for production use -- see
// CdrArchive_test.cpp's FakeSink. Compiled on every platform (this is what
// makes record()/wipeAll()'s no-op/wipe contract testable on host, where
// PD_ETH_HAS_SD is never defined and init() is therefore always a no-op).
Sink* setSinkForTest(Sink* sink);

// Test-only: current queue depth, so a test can assert push/drop behaviour
// without a Sink at all.
size_t pendingForTest();

}  // namespace cdrarchive

#endif
