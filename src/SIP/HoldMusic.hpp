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

private:
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
};

#endif
