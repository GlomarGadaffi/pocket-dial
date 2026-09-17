#ifndef RTP_SENDER_HPP
#define RTP_SENDER_HPP

// RtpSender — the "media beachhead": the first server-side RTP path in pocket-dial.
//
// Until now the ESP32 touched NO media: RTP flowed peer-to-peer between phones and
// the server was a pure signaling proxy/registrar. This module stands up a one-way
// RTP SENDER: when a phone dials the virtual "media" extension (440), the server
// answers with its OWN SDP and streams a continuously-synthesized G.711 µ-law tone
// to the caller's RTP address until BYE/CANCEL. Hearing audio proves the RTP pipe.
//
// Layering / portability:
//   * The pure DSP + packetization helpers (µ-law encode, tone synthesis, RTP header
//     build) are PLATFORM-INDEPENDENT and host-unit-tested (see tests/Rtp_test.cpp).
//   * The actual UDP socket + the 20 ms FreeRTOS pacing task are ESP-ONLY and guarded
//     by `#if defined(ESP_PLATFORM)`. On host these compile to no-op stubs so the
//     desktop gtest build (build_desktop) still builds & links.
//
// Concurrency cap: ONE concurrent stream. A second dial of 440 while a stream is
// live is rejected by the caller (onInvite) with 486 Busy Here. isActive() is the
// single source of truth the registrar checks; it is updated under an internal
// guard so the SIP thread and the media task never race on the slot.
//
// No hot-path heap: the tone is synthesized 20 ms (160 samples) at a time into a
// fixed stack/member buffer; nothing is allocated per packet.

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
#include <lwip/sockets.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#elif defined(__linux__)
#include <netinet/in.h>
#include <thread>
#elif defined _WIN32 || defined _WIN64
#include <WinSock2.h>
#endif

#include <cstdint>
#include <atomic>
#include <string>
#include <array>
#include <mutex>
#include <functional>

#include "L2RtpFrame.hpp"

class RtpSender
{
public:
	// Optional per-frame audio source: called once per 20 ms tick to fill `outUlaw`
	// with `count` µ-law samples. Returns false to mean "nothing this frame" (the
	// sender falls back to silence, not the test tone, when a provider is attached).
	// Leave unset (the default) for the plain 440 test-tone stream.
	using FrameProvider = std::function<bool(uint8_t* outUlaw, size_t count)>;

	// G.711 @ 8 kHz, 20 ms ptime → 160 samples / packet. Payload type 0 (PCMU).
	static constexpr int    SAMPLE_RATE_HZ   = 8000;
	static constexpr int    PTIME_MS         = 20;
	static constexpr int    SAMPLES_PER_PKT  = SAMPLE_RATE_HZ * PTIME_MS / 1000; // 160
	static constexpr uint8_t PAYLOAD_TYPE_PCMU = 0;
	static constexpr int    RTP_HEADER_BYTES  = 12;
	// One RTP packet = 12-byte header + 160 µ-law bytes.
	static constexpr int    PACKET_BYTES      = RTP_HEADER_BYTES + SAMPLES_PER_PKT;

	// Default synthesized tone frequency (continuous European-style dial/test tone).
	static constexpr int    DEFAULT_TONE_HZ   = 425;

	// ── Pure, platform-independent primitives (host-unit-tested) ────────────────

	// ITU-T G.711 µ-law encode of one 16-bit linear PCM sample. Standard reference
	// implementation: bias 0x84, segment search, 8-bit companded byte (inverted).
	static uint8_t linearToUlaw(int16_t pcm);

	// Encode `count` PCM16 samples from `in` into `out` (µ-law). `out` must hold
	// `count` uint8_t. No allocation, fully bounds-driven by `count`. Safe no-op
	// on null/empty. Returns the number of samples written. Mirror of
	// RtpReceiver::mulawDecodeBuffer.
	static size_t ulawEncodeBuffer(const int16_t* in, size_t count, uint8_t* out);

	// Fill `out` with `count` µ-law samples of a sine tone at `freqHz`, advancing the
	// caller's running phase `phase` (in radians) so successive frames are continuous
	// (no click at the 20 ms boundary). amplitude is 0..1 of full scale.
	static void synthTone(uint8_t* out, int count, double freqHz,
		double& phase, double amplitude = 0.5);

	// Build a 12-byte RTP header (RFC 3550) into `out` in network byte order:
	//   V=2, P=0, X=0, CC=0, M=marker, PT=pt, seq, timestamp, ssrc.
	// `out` must have room for RTP_HEADER_BYTES. Used by the task AND the host tests.
	static void buildRtpHeader(uint8_t* out, bool marker, uint8_t pt,
		uint16_t seq, uint32_t timestamp, uint32_t ssrc);

	// ── Stream lifecycle (the registrar drives these from the SIP thread) ───────

	RtpSender();
	~RtpSender();

	// True while a stream is live. The registrar checks this to enforce the single-
	// stream cap (a 2nd dial of 440 is rejected 486 while this is true).
	bool isActive() const { return _active.load(std::memory_order_acquire); }

	// The UDP port the server sources RTP from (advertised in the 440 200-OK SDP).
	int serverRtpPort() const { return _serverRtpPort; }

	// Start streaming to destIp:destPort, tagged with callID so stop() only stops the
	// matching dialog (a stale BYE for an old call is ignored). With no `provider`,
	// streams the synthesized 440 test tone (existing behavior, unchanged); with a
	// `provider`, pulls real audio from it each frame instead (silence on underrun).
	// Returns false if a stream is already active (cap reached) or the socket/task
	// could not be created. On host this is a guarded no-op that still flips _active
	// so the SDP-answer / cap logic is exercisable in tests.
	bool start(const std::string& destIp, uint16_t destPort, const std::string& callID, FrameProvider provider = nullptr);

	// Stop the stream IF it belongs to `callID` (or unconditionally if callID empty).
	// Idempotent: safe to call on an already-idle sender. Frees the socket, signals
	// the task to exit, and clears _active. Returns true if a stream was stopped.
	bool stop(const std::string& callID);

	// The Call-ID of the live stream ("" when idle). Lets onCancel/onBye match.
	std::string activeCallId() const;

private:
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	static void taskTrampoline(void* arg);
	void runLoop();                       // 20 ms-paced sender loop (Core 0)
	int               _sock = -1;
	// Cross-thread control flags (no binary semaphore — that was prone to a stale
	// "give" surviving a timed-out join and freeing the next stream's socket early).
	//   _stopRequested : the SIP thread asks the media task to finish its frame & exit.
	//   _taskRunning   : true from just-before-launch until the task's very last act.
	//                    The task OWNS its teardown (closes its own socket, clears the
	//                    slot) and clears _taskRunning LAST, so the destructor can join
	//                    on it and start() can refuse to overlap a dying task.
	std::atomic<bool> _stopRequested{false};
	std::atomic<bool> _taskRunning{false};
	sockaddr_in       _dest{};

	// L2 RTP TX (Issue #282 / #329)
	bool                                     _l2Ready = false;
	l2rtp::Endpoint                          _l2Ep{};
	uint16_t                                 _l2IpIdent = 0;
	uint32_t                                 _l2ResolveTicks = 0;
	std::array<uint8_t, l2rtp::kHeaderBytes> _l2Template{};
	uint32_t                                 _l2TxErrors = 0;
#elif defined(__linux__)
	// Issue #82: real Linux media path (the ESP-only block above was the sole
	// gap keeping pocket-dial's Linux desktop build signaling-only, per
	// RtpSender's own class comment). Mirrors the ESP shape one-for-one:
	// FreeRTOS task -> std::thread, vTaskDelayUntil -> sleep_until pacing. The
	// one deliberate divergence is stop() joining synchronously instead of the
	// ESP path's fire-and-forget _taskRunning poll — see stop()'s own comment
	// in RtpSender.cpp for why, and the bounded cost of that choice.
	void runLoop();
	int          _sock = -1;
	sockaddr_in  _dest{};
	std::thread  _senderThread;
	std::atomic<bool> _stopRequested{false};
#endif

	std::atomic<bool> _active{false};
	int               _serverRtpPort;     // fixed dedicated media port

	// Guards _callID and the start/stop transition so the SIP thread and the media
	// task never race the slot. Non-recursive (matches the codebase convention).
	mutable std::mutex _slotMutex;
	std::string        _callID;           // owner of the live stream
	FrameProvider      _provider;
};

#endif
