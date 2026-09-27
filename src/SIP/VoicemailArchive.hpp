#ifndef VOICEMAIL_ARCHIVE_HPP
#define VOICEMAIL_ARCHIVE_HPP

// VoicemailArchive -- Issue #246 (voicemail Stage 3 of #194): the SD-card
// flush pipeline for a finished VoicemailLeg recording.
//
// Mirrors CdrArchive.hpp's queue+writer-task shape exactly (see that header's
// class comment for the full "why a queue at all" reasoning -- sdspi's
// poll_busy() busy-spins and routine card GC stalls 100-250 ms, so nothing on
// the SIP thread may ever fopen/fwrite). The difference is the payload: a CDR
// row is a fixed ~600 bytes and copies into the queue slot directly; a
// voicemail recording is up to ~700 KB, far too large to copy into a small
// fixed-capacity ring. Instead, enqueue() memcpy's the recorded mu-law into a
// DEDICATED PSRAM STAGING BUFFER (one per queue slot, allocated once at boot
// alongside the leg buffers -- see PoolConfig.hpp's
// POCKETDIAL_MAX_VOICEMAIL_LEGS budget comment) and the queue itself carries
// only the small QueuedRecording metadata (which staging slot, whose call,
// how long). This is what lets releaseVoicemailLeg() stay exactly as it was
// -- stop the RTP pair, reset() the leg, done, immediately -- rather than
// needing to defer reset() until the writer task finishes reading the leg's
// OWN buffer.
//
// PLATFORM SHAPE, same convention as CdrArchive.hpp/LogQueue.hpp/TimeSync.hpp:
// the pure pieces (buildWavHeader, WriterQueue, drainAll) are plain C++17, no
// FreeRTOS, no filesystem, fully host-unit-tested. Only the production Sink
// (real fopen/rename against /sdcard/vm) and the writer task are ESP-only,
// gated on PD_ETH_HAS_SD specifically -- not bare ESP_PLATFORM -- for the
// same reason CdrArchive.hpp gates that way (wifi/lan8720 builds don't even
// declare pd_sd_mounted()).

#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string_view>
#include <vector>

namespace vmarchive
{

// µ-law WAV header size (RIFF+WAVE, 18-byte fmt, 4-byte fact, data chunk
// header): 12 + 26 + 12 + 8 = 58 bytes exactly. See buildWavHeader()'s
// implementation for the byte-for-byte layout HoldMusic::parseUlawWav()
// expects on the read side -- VoicemailArchive_test.cpp round-trips through
// that exact parser rather than asserting on offsets by hand.
constexpr size_t kWavHeaderBytes = 58;

// Build the header for a mu-law WAV file of `dataBytes` audio, into `out`
// (which must be at least kWavHeaderBytes). Pure, no allocation, no clock.
void buildWavHeader(size_t dataBytes, uint8_t* out);

// One queued flush job: which staging slot holds the audio (see the class
// comment), whose call it was, and when. Fixed size, no heap -- the SIP
// thread pushes one of these, never the audio itself.
struct QueuedRecording
{
	int stagingSlot = -1;
	// "" (extension[0] == '\0') marks an empty/invalid slot, same convention
	// as CdrArchive::QueuedLine's date[0] sentinel.
	char extension[32] = {};
	char callId[128] = {};
	// 0 means "wall clock never synced" -- see the class comment on
	// enqueue()'s fallback naming, unlike cdrarchive::record() this does NOT
	// drop the message; a voicemail is worth more than its timestamp.
	uint64_t epochSeconds = 0;
	// Monotonically increasing per-process counter, used for the filename
	// when epochSeconds is 0 (or always, alongside it, so two messages in
	// the same second never collide).
	uint64_t sequence = 0;
	size_t length = 0;
};

// ── Sink: what actually persists a finished recording ───────────────────────
// Production implementation (VoicemailArchive.cpp, PD_ETH_HAS_SD only) writes
// /sdcard/vm/<extension>/<epochSeconds-or-boot-seq>.wav.tmp, closes it,
// renames to the final .wav, THEN appends the metadata index row -- in that
// order, so a crash mid-write leaves an orphaned .tmp (swept at boot) rather
// than an index entry pointing at a truncated or missing file (#194 prereq
// 1b's write-order rule). Tests substitute a FakeSink that records the call
// and the mu-law bytes it was handed, so the queue/drain/stage pipeline is
// exercised with zero real file I/O.
class Sink
{
public:
	virtual ~Sink() = default;
	virtual void write(const QueuedRecording& rec, const uint8_t* mulaw) = 0;
	// Issue #450: factory reset. Deletes every stored recording, greeting and
	// index under the archive root. Pure virtual on purpose, so no Sink can
	// silently skip it.
	virtual void wipe() = 0;
};

// ── WriterQueue: the enqueue/dequeue mechanics, decoupled from FreeRTOS ─────
// Same shape and thread-safety contract as cdrarchive::WriterQueue (see that
// class's doc comment) -- a LEAF lock, safe to take from inside
// RequestsHandler::_mutex, push() never blocks (drops and returns false when
// full rather than stalling the SIP thread).
class WriterQueue
{
public:
	explicit WriterQueue(size_t capacity);

	bool push(const QueuedRecording& rec);
	bool pop(QueuedRecording& out);
	size_t size() const;
	void clear();

private:
	mutable std::mutex _m;
	std::vector<QueuedRecording> _buf;
	size_t _head = 0;
	size_t _count = 0;
};

// Drains everything currently in `queue` to `sink`, in FIFO order, reading
// each recording's audio from `stagingBufs[rec.stagingSlot]`. This is the
// entire body of the ESP writer task's loop and what
// VoicemailArchive_test.cpp calls directly against a FakeSink.
//
// `afterWrite`, if set, is called once per record immediately after
// `sink.write()` RETURNS for it -- i.e. once that staging buffer is
// provably safe to overwrite again. This exists so a caller (RequestsHandler)
// can clear its own "this staging slot is still in flight" bookkeeping at
// the one moment that's actually true, rather than at enqueue time or at
// pop time, either of which would let a new deposit reuse (and silently
// corrupt) a staging buffer the write to SD hadn't actually finished
// reading from yet. This module stays ignorant of what that bookkeeping
// is -- it only promises the callback fires after the read, never before.
void drainAll(WriterQueue& queue, Sink& sink, uint8_t* const* stagingBufs,
	const std::function<void(const QueuedRecording&)>& afterWrite = nullptr);

#if defined(PD_ETH_HAS_SD)
// The production Sink: writes /sdcard/vm/<extension>/<name>.wav.tmp, closes
// it, renames to .wav, THEN appends the metadata index row -- in that order
// (#194 prereq 1b's write-order rule: a crash mid-write leaves an orphaned
// .tmp, swept at boot, never an index entry pointing at a truncated file).
// `<name>` is epochSeconds when the wall clock has synced, else
// "boot-<sequence>" (see QueuedRecording's doc comment) -- never dropped for
// lack of a timestamp the way cdrarchive::record() drops a CDR row, since a
// voicemail is worth more than its timestamp. Declared only under
// PD_ETH_HAS_SD, same reason CdrArchive.hpp's Sink split is gated that way:
// wifi/lan8720 builds don't declare pd_sd_mounted() at all.
Sink& productionSink();
#endif

// ── Source: the read counterpart, for the retrieval menu ────────────────────
// Added once the deposit side had somewhere real to read FROM -- see
// pocket_dial_246_voicemail.md's advisor note for why this had to exist
// before ext 796 could route anywhere. Reads index.csv's rows exactly as
// Sink/FatFsSink appends them.
//
// Delete does NOT rewrite index.csv -- a rewrite is not crash-safe (a
// power loss mid-rewrite can lose the whole index), and the class comment
// above already commits this file to an append-only discipline. Instead a
// delete APPENDS A TOMBSTONE row, distinguished from a real entry row by a
// leading "#DEL," the two names an index.csv line can never start with a
// real message name -- both name shapes come from QueuedRecording's own
// naming rule (epochSeconds or "boot-<sequence>"), never a "#". Every
// Source implementation must treat the LATEST tombstone for a given name
// as final: once tombstoned, a name never re-appears (the sequence only
// grows, deposits never reuse a retired name).
struct MessageInfo
{
	// The filename stem this message's audio lives under -- see
	// QueuedRecording::sequence's doc comment for the naming rule. Read
	// back a message's body with this same name via Source::readMessage().
	char name[48] = {};
	uint64_t epochSeconds = 0;   // 0 if the wall clock had never synced at deposit time
	size_t length = 0;           // raw mu-law byte count, NOT counting the WAV header
	char callId[128] = {};
};

// A row starting with this can never collide with a real entry row -- see
// MessageInfo's doc comment above.
constexpr const char* kTombstonePrefix = "#DEL,";

// ── Pure index.csv line parsing (host-unit-tested, no filesystem) ───────────
// Used by FatFsSource under PD_ETH_HAS_SD; split out and left unconditional
// so the parsing logic itself is directly testable on host, mirroring
// buildWavHeader() being pure while FatFsSink (its only real caller) stays
// ESP-gated.

// Strips a trailing \n and/or \r from `line` in place, as fgets() leaves it.
void chompIndexLine(char* line);

// True if `line` is a tombstone row ("#DEL,<name>"), copying <name> into
// `nameOut` (up to `nameCap`). False (nameOut left untouched) for anything
// else, including a real entry row.
bool parseTombstoneLine(const char* line, char* nameOut, size_t nameCap);

// Parses a real entry row "name,epochSeconds,length,callId" into `info`.
// Only the first three commas are structural -- everything after the third
// is the callId verbatim (the write side never escapes it either). Returns
// false (info left untouched) if the line has fewer than three commas, or
// the name field is empty or too long for MessageInfo::name. A tombstone
// row ("#DEL,<name>", exactly one comma) always fails this parse and
// returns false, so callers may check tombstone-then-entry in either
// order -- FatFsSource::listMessages() still checks tombstones in a
// separate first pass, since a tombstone can appear AFTER the entry row
// it retires.
bool parseEntryLine(const char* line, MessageInfo& info);

class Source
{
public:
	virtual ~Source() = default;

	// Fills `out[0..N)` with up to `maxCount` non-tombstoned messages for
	// `extension`, in the order index.csv recorded them (oldest first) --
	// the menu decides playback/deletion order, not this call. Returns N.
	// Returns 0, not an error, for an extension with no mailbox directory
	// yet (nobody has ever left it a message).
	virtual size_t listMessages(const char* extension, MessageInfo* out, size_t maxCount) const = 0;

	// Reads message `name`'s raw mu-law body (the .wav file's audio, past
	// its header) into `out`, up to `capacity` bytes. Returns the number
	// of bytes actually read, or 0 if the message doesn't exist, can't be
	// opened, or is already tombstoned. A message longer than `capacity`
	// is refused outright (returns 0), never truncated -- a silently
	// clipped playback with no signal to the caller is worse than a clean
	// refusal (callers size `capacity` to POCKETDIAL_VOICEMAIL_MAX_MESSAGE_BYTES,
	// which nothing on this Source's write side can ever exceed).
	virtual size_t readMessage(const char* extension, const char* name,
		uint8_t* out, size_t capacity) const = 0;

	// Appends a tombstone row for `name` -- see the class comment for why
	// this never rewrites index.csv or deletes the underlying .wav file
	// (freeing that disk space is a separate, later concern; nothing reads
	// a tombstoned .wav again once this returns). Idempotent: tombstoning
	// an already-tombstoned or nonexistent name still returns true, since
	// the end state ("this name never lists or reads again") already
	// holds either way.
	virtual bool markDeleted(const char* extension, const char* name) = 0;
};

#if defined(PD_ETH_HAS_SD)
// The production Source, paired with productionSink() above -- same
// PD_ETH_HAS_SD gate, same /sdcard/vm layout, same index.csv it reads.
Source& productionSource();
#endif

}  // namespace vmarchive

#endif
