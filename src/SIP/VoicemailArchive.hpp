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
void drainAll(WriterQueue& queue, Sink& sink, uint8_t* const* stagingBufs);

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

}  // namespace vmarchive

#endif
