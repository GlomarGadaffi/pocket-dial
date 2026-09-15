#ifndef HOLD_MUSIC_HPP
#define HOLD_MUSIC_HPP

// HoldMusic — music on hold for parked callers, "radio station" style (issue #162).
//
// THE MODEL. One global clip cursor, not one per listener. Every parked leg hears
// the SAME point in the track, and a late joiner lands mid-song exactly as if they
// had tuned into a broadcast. This is deliberate and it is what makes the feature
// cheap: the 20 ms tick reads 160 bytes ONCE and fans the identical payload to
// every listener, so per-leg cost is an RTP header plus a sendto — no per-leg
// decode, no mixing, no MixBus. Park is strictly one-way: there is no "self" to
// subtract, and the output is identical for everyone, so the conference mixer
// would be the wrong tool even if it were free.
//
// WHY NOT RtpSender. RtpSender is a 4-instance pool carrying a receive side and a
// jitter buffer, and it binds one fixed port. Ten parked callers need ten
// transmit-only streams that share a payload; standing up ten RtpSenders would
// allocate ten receive paths nobody reads and ten playout buffers nobody fills.
//
// THE CLIP LIVES IN RAM, NOT ON THE CARD. loadClip() reads the whole file once,
// into PSRAM when available. This is the single most important design decision
// here: it keeps the SD card entirely out of the media path. ESP-IDF's sdspi
// poll_busy() is a hard busy-spin with no vTaskDelay, and routine card
// garbage-collection stalls of 100-250 ms are normal — against a 20 ms tick that
// is audible dropout on every listener at once. A 102-second µ-law clip is ~816 KB
// against 8 MB of PSRAM, so there is no reason to stream it. See docs and #194's
// SD write-discipline section for the failure mode being avoided.
//
// FORMAT. G.711 µ-law, 8 kHz, mono — the wire format itself (WAVE_FORMAT_MULAW,
// tag 7). Playback is then a memcpy from the clip into the RTP payload: no decode,
// no resample, no transcode. Prepare clips on a desktop:
//     ffmpeg -i music.mp3 -ar 8000 -ac 1 -acodec pcm_mulaw moh.wav
//
// LAYERING, as RtpSender/RtpReceiver do it: the parser, the cursor arithmetic and
// the gain table are pure and host-unit-tested; the socket, the PSRAM allocation
// and the 20 ms FreeRTOS task are ESP-only behind `#if defined(ESP_PLATFORM)` and
// compile to no-op stubs on the desktop build.

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
#include <lwip/sockets.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#elif defined(__linux__)
#include <netinet/in.h>
#elif defined _WIN32 || defined _WIN64
#include <WinSock2.h>
#endif

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>

#include "PoolConfig.hpp"

class HoldMusic
{
public:
	// G.711 @ 8 kHz, 20 ms — identical to RtpSender's constants by necessity, since
	// these are the two ends of the same wire format.
	static constexpr int     SAMPLE_RATE_HZ  = 8000;
	static constexpr int     PTIME_MS        = 20;
	static constexpr size_t  BYTES_PER_TICK  = SAMPLE_RATE_HZ * PTIME_MS / 1000;  // 160
	static constexpr uint8_t PAYLOAD_TYPE_PCMU = 0;
	static constexpr int     RTP_HEADER_BYTES  = 12;

	// One listener per park orbit. Sized from the orbit count rather than picked:
	// every parked call can be listening simultaneously and none of them should be
	// the one that silently gets nothing.
	static constexpr size_t  kMaxListeners = POCKETDIAL_PARK_SLOTS;

	// µ-law silence. NOT 0x00 — that is full-scale negative in µ-law and would be a
	// loud click. 0xFF is the µ-law code for zero (see RtpReceiver::mulawDecode's
	// test vectors, which pin 0xFF -> 0).
	static constexpr uint8_t kUlawSilence = 0xFF;

	// Pacing-task stack. Was 3072 against a bounded 172-byte packet buffer plus
	// a handful of locals -- issue #218 changed that: a tap fired under this
	// same tick can now reach MediaBridge::feedMohTick() -> TelephonyAnchor
	// Client::writeAudio(), which puts its own ~320-sample PCM16 decode buffer
	// (640 bytes) and a ~1 KB chunked-HTTP framing buffer on THIS task's stack,
	// plus whatever esp_http_client/mbedTLS use under a real (possibly slow,
	// possibly TLS-handshaking) network write. Bumped defensively rather than
	// left at the old, now-wrong figure. This is deliberately NOT a round
	// number picked by feel: runLoop() logs uxTaskGetStackHighWaterMark() once
	// the listener table has been exercised, so the value can be trimmed from
	// measurement instead of guessed. Check the boot log's "stack high-water"
	// line on the next hardware pass -- this number has not been measured
	// against the new call chain yet.
	static constexpr int kTaskStackBytes = 6144;

	// ── Pure, platform-independent primitives (host-unit-tested) ────────────────

	// Where the µ-law audio starts and how much of it there is, for a WAV in
	// WAVE_FORMAT_MULAW (tag 7), 8 kHz, mono. Walks the RIFF chunk list properly
	// rather than assuming a 44-byte header: a µ-law WAV carries an 18-byte `fmt `
	// plus a `fact` chunk, so the canonical-PCM offset is simply wrong here, and a
	// writer may legally insert LIST/INFO chunks before `data`.
	//
	// Returns false — leaving `outOffset`/`outBytes` untouched — for anything that
	// is not 8 kHz mono µ-law. Rejecting a 44.1 kHz stereo PCM file loudly at load
	// is much better than playing it as if it were µ-law, which is what a naive
	// "skip 44 bytes" reader does: full-scale noise at four times the intended rate.
	static bool parseUlawWav(const uint8_t* data, size_t len,
	                         size_t& outOffset, size_t& outBytes);

	// Advance a cursor by one tick's worth of bytes within a clip of `clipBytes`,
	// wrapping seamlessly. Pulled out and tested because an off-by-one here is an
	// audible click once per loop, which is the kind of defect that gets described
	// as "it sounds slightly wrong" and never gets found.
	static size_t advanceCursor(size_t cursor, size_t clipBytes);

	// Build a 256-entry µ-law -> µ-law gain table for `gainDb`.
	//
	// Gain on µ-law is a byte lookup, which is why runtime volume is effectively
	// free here and worth having: decode the code, scale, re-encode, once per
	// table rather than once per sample. This matters in practice because hold
	// music is usually authored quiet — a real 3CX MoH file measured -28.6 dBFS
	// peak / -44.9 dBFS RMS, because the PBX is expected to boost at playback.
	// Prefer normalising the clip at conversion time (encoding a boosted signal
	// measured ~4 dB better SNR than boosting after µ-law quantisation), and use
	// this for the operator's trim on top.
	static void buildGainTable(float gainDb, uint8_t outTable[256]);

	// ── Lifecycle (SIP thread) ─────────────────────────────────────────────────

	HoldMusic();
	~HoldMusic();

	// Load a µ-law WAV into RAM (PSRAM when present). Idempotent per path; loading
	// a different path replaces the clip. Returns false and leaves any previous
	// clip intact if the file is missing, unreadable or not 8 kHz mono µ-law —
	// keeping whatever was already playing rather than dropping every listener
	// into silence because someone uploaded the wrong file.
	bool loadClip(const std::string& path);

	bool   isLoaded()   const { return _clipBytes.load(std::memory_order_acquire) > 0; }
	size_t clipBytes()  const { return _clipBytes.load(std::memory_order_acquire); }
	// Clip length in whole seconds, for the dashboard.
	unsigned clipSeconds() const { return static_cast<unsigned>(clipBytes() / SAMPLE_RATE_HZ); }

	// Operator trim in dB, applied through the gain table above. 0 is unity.
	void  setGainDb(float db);
	float gainDb() const { return _gainDb.load(std::memory_order_acquire); }

	// The UDP port listeners are told to expect audio from, for the SDP answer.
	// 0 until start() has bound one.
	int localPort() const { return _localPort.load(std::memory_order_acquire); }

	// Bind the socket and start the 20 ms pacing task. Safe to call repeatedly.
	// Returns false if no clip is loaded or the socket/task could not be created —
	// park must then fall back to its old silent hold rather than answering with a
	// port that will never carry audio.
	bool start();
	void stop();

	// Add a parked leg. Returns a listener id, or -1 when full / not running.
	// `destIp`/`destPort` come from the parked party's own SDP.
	int  addListener(const std::string& destIp, uint16_t destPort);
	void removeListener(int id);
	unsigned listenerCount() const;

	// Issue #218: a second, smaller kind of listener for a leg that has no RTP
	// destination of its own to register above -- a media-anchored (555) call
	// on hold. MediaBridge already owns that leg's real transport (it decodes
	// the handset's RTP and hands PCM16 to the AnchorClient itself), so it
	// doesn't want a UDP packet sent anywhere; it wants the shared clip's raw
	// bytes each tick so it can inject them into its OWN outbound-to-anchor
	// path in place of the handset's real audio. Same "one cursor, everyone
	// hears the same instant" model as the RTP listeners above -- this is
	// still a pull off that one cursor, not a second stream.
	//
	// Raw function pointer + context, not std::function: this fires from the
	// pacing task's own real-time loop and must not touch the heap. Fixed at
	// POCKETDIAL_MAX_ANCHOR_CALLS slots -- one tap per anchor call that could
	// be held, at most, which is the same bound _mediaBridges is sized to.
	using TapFn = void (*)(void* ctx, const uint8_t* ulawTick, size_t n);
	// Registers a tap; returns an id (>=0), or -1 if the tap table is full.
	int  addTap(TapFn fn, void* ctx);
	void removeTap(int id);

	// Test-only: drives exactly the per-tick body runLoop() runs (read the
	// cursor, apply gain, snapshot+invoke taps, advance the cursor) without
	// the real 20 ms task or socket, neither of which exist on host. A no-op
	// if no clip is loaded. Compiled on every platform, like RequestsHandler's
	// other test-only seams, so a host test can exercise addTap()'s actual
	// delivery rather than only its bookkeeping. Invokes taps in the same
	// lock-released order runLoop() does (see tickLocked()'s doc comment) —
	// this deliberately does NOT take a shortcut of calling taps under the
	// lock just because there is no real fan-out here to interleave with;
	// host tests should exercise the actual production ordering.
	void deliverTickForTest();

private:
	// A tap registration, copied OUT of the tap table by value under _mutex
	// so it can be invoked after the lock is released. See tickLocked()'s
	// doc comment for why the invocation itself must not happen while this
	// class's _mutex is still held.
	struct TapSnapshot
	{
		TapFn fn  = nullptr;
		void* ctx = nullptr;
	};

	// Shared by runLoop() (ESP) and deliverTickForTest() (host): fills `out`
	// with BYTES_PER_TICK gain-adjusted bytes at the current cursor position,
	// copies (does NOT invoke) every registered tap into `tapsOut` (caller-
	// sized to at least POCKETDIAL_MAX_ANCHOR_CALLS), sets `tapCount`, and
	// advances the cursor. Caller must hold _mutex. Returns false (leaving
	// everything else untouched) if no clip is loaded.
	//
	// Taps are snapshotted rather than invoked here on purpose (issue #218
	// follow-up, caught in review): a tap can reach MediaBridge::feedMohTick()
	// -> TelephonyAnchorClient::writeAudio(), a real network write that can
	// block for the WHOLE 2 s HTTP client timeout on a congested trunk. If
	// that happened while THIS _mutex were held, the SIP thread's own
	// addTap()/removeTap() calls (setHeld()/stopBridge(), taken under
	// RequestsHandler's engine lock) would stall behind it too — meaning one
	// slow trunk write could freeze registration/INVITE/BYE processing for
	// every call on the box, not just delay one parked caller's audio. The
	// caller must invoke the snapshotted taps only AFTER releasing _mutex.
	bool tickLocked(uint8_t out[BYTES_PER_TICK], TapSnapshot* tapsOut, size_t& tapCount);

	struct Listener
	{
		bool     used     = false;
		uint32_t ssrc     = 0;
		uint16_t seq      = 0;
		uint32_t timestamp = 0;
		sockaddr_in dest{};
	};

	void freeClipLocked();

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	static void taskTrampoline(void* arg);
	void runLoop();
	int  _sock = -1;
	std::atomic<bool> _stopRequested{false};
	std::atomic<bool> _taskRunning{false};
	// Touched only by the pacing task, so no synchronisation is needed or wanted.
	uint32_t _txErrors = 0;   // failed sendto()s — a silent gap otherwise
	uint32_t _ticks    = 0;   // drives the one-shot stack high-water report
#endif

	// The clip. Owned here, freed on destruction / replacement.
	uint8_t*            _clip = nullptr;
	std::atomic<size_t> _clipBytes{0};

	// THE single cursor — the whole radio-station idea in one variable. Touched
	// only by the pacing task.
	size_t _cursor = 0;

	std::atomic<int>   _localPort{0};
	std::atomic<bool>  _running{false};
	std::atomic<float> _gainDb{0.0f};

	// Guards the listener table and the clip pointer against the SIP thread
	// adding/removing legs while the pacing task is fanning a frame out.
	mutable std::mutex _mutex;
	Listener           _listeners[kMaxListeners];
	uint8_t            _gainTable[256];
	bool               _gainIsUnity = true;

	// Issue #218's taps (see addTap()'s doc comment). Guarded by the same
	// _mutex as _listeners -- the pacing task reads this table under lock
	// alongside the listener fan-out, in the same tick.
	struct Tap
	{
		bool  used = false;
		TapFn fn   = nullptr;
		void* ctx  = nullptr;
	};
	Tap _taps[POCKETDIAL_MAX_ANCHOR_CALLS];
};

#endif
