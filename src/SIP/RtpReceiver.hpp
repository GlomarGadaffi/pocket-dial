#ifndef RTP_RECEIVER_HPP
#define RTP_RECEIVER_HPP

// RtpReceiver — the inbound media path, mirror image of RtpSender.
//
// Where RtpSender stands up a one-way RTP *source* (synthesize tone → µ-law
// encode → RTP packetize → sendto), RtpReceiver stands up the inverse one-way
// RTP *sink*: bind a UDP socket, recvfrom RTP datagrams, parse the RFC 3550
// header, validate the payload type (PCMU/µ-law only), and hand the µ-law
// payload to a caller-supplied sink. It is foundational infrastructure that
// three future consumers all need but none of them lives here:
//   (1) Voicemail record — write the raw µ-law frames to the `prompts` flash
//       partition (esp_partition_write, fixed-frame-size raw layout).
//   (2) SBC trunk B2BUA bridge — hand each frame to the other call leg's
//       RtpSender-style egress so audio is relayed between two dialogs.
//   (3) Call recording — tee the µ-law (or decoded PCM16) to storage.
// RtpReceiver deliberately knows NONE of that: the `Sink` callback is the only
// coupling point, so this module stays a clean standalone class. Integration
// into RequestsHandler is a separate, later step.
//
// Layering / portability (identical to RtpSender):
//   * The pure parse + DSP helpers (RTP header parse, µ-law DECODE) are
//     PLATFORM-INDEPENDENT and host-unit-tested (see tests/RtpReceiver_test.cpp).
//   * The actual UDP socket + the receive FreeRTOS task are ESP-ONLY and guarded
//     by `#if defined(ESP_PLATFORM)`. On host they compile to no-op stubs so the
//     desktop gtest build still builds & links and start()/stop()/isActive()
//     remain exercisable.
//
// Concurrency cap: ONE concurrent stream (matches RtpSender). A second start()
// while a stream is live returns false. isActive() is the single source of truth
// for the cap, updated under an internal guard so the SIP thread and the receive
// task never race the slot.
//
// No hot-path heap: each datagram is read into a fixed member/stack buffer and
// decoded into a fixed buffer; nothing is allocated per packet. The Sink is
// invoked with pointers into that fixed buffer (the sink must consume/copy
// synchronously — it must not retain the pointer past the callback).

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
#include <lwip/sockets.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#elif defined(__linux__)
#include <netinet/in.h>
#elif defined _WIN32 || defined _WIN64
#include <WinSock2.h>
#endif

#include <cstddef>
#include <cstdint>
#include <atomic>
#include <functional>
#include <mutex>
#include <string>

class RtpReceiver
{
public:
	// G.711 @ 8 kHz, 20 ms ptime → 160 samples / packet. Payload type 0 (PCMU).
	// These MUST stay in lock-step with RtpSender's matching constants: the two
	// modules are the two ends of the same wire format.
	static constexpr int     SAMPLE_RATE_HZ    = 8000;
	static constexpr int     PTIME_MS          = 20;
	static constexpr int     SAMPLES_PER_PKT   = SAMPLE_RATE_HZ * PTIME_MS / 1000; // 160
	static constexpr uint8_t PAYLOAD_TYPE_PCMU = 0;
	static constexpr int     RTP_HEADER_BYTES  = 12;

	// Largest RTP datagram we are willing to buffer. A PCMU/20ms packet is
	// 12 + 160 = 172 bytes; we allow generous slack for CSRC lists / a header
	// extension / non-20ms ptime without ever heap-allocating. Anything larger
	// is read but truncated by the kernel to this cap; parseRtp() then bounds-
	// checks against the actual byte count so a short/oversize read is safe.
	static constexpr int     MAX_DATAGRAM_BYTES = 512;

	// Parsed view of one RTP packet (RFC 3550 §5.1). `payload`/`payloadLen`
	// point INTO the caller's receive buffer — no copy, no allocation. Valid
	// only while that buffer is alive.
	struct RtpPacket
	{
		uint8_t        version     = 0;
		bool           marker      = false;
		uint8_t        payloadType = 0;
		uint16_t       seq         = 0;
		uint32_t       timestamp   = 0;
		uint32_t       ssrc        = 0;
		const uint8_t* payload     = nullptr;  // → into the source datagram buffer
		size_t         payloadLen  = 0;
	};

	// ── RFC 4733 telephone-event (DTMF over RTP) ────────────────────────────────
	// Named events ride the SAME RTP stream as audio, on a DYNAMIC payload type the
	// two ends negotiate in SDP (`a=rtpmap:<pt> telephone-event/8000`). There is no
	// fixed number for it — 101 is merely a common choice — so the PT must be taken
	// from the offer at call setup and handed to setDtmfPayloadType(). Until then
	// the receiver has no way to tell an event packet from a codec it does not
	// speak, which is why kDtmfPayloadTypeUnset is the default.
	static constexpr uint8_t kDtmfPayloadTypeUnset = 0xFF;

	// One decoded RFC 4733 §2.3 event payload (4 bytes on the wire):
	//
	//    0                   1                   2                   3
	//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//   |     event     |E|R| volume    |          duration             |
	//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	struct DtmfEvent
	{
		uint8_t  event    = 0;      // 0-9 digits, 10 '*', 11 '#', 12-15 A-D, 16 flash
		bool     end      = false;  // E bit: this is a (retransmitted) end packet
		uint8_t  volume   = 0;      // 6 bits, -dBm0 (0 loudest, 63 quietest)
		uint16_t duration = 0;      // 8 kHz timestamp units, network byte order
	};

	// Parse a telephone-event payload. Pure and bounds-checked: returns false on a
	// short buffer, leaving `out` untouched. Does NOT validate the event code — a
	// caller wanting only DTMF filters with dtmfEventToChar().
	static bool parseTelephoneEvent(const uint8_t* payload, size_t len, DtmfEvent& out);

	// Map an RFC 4733 event code to its keypad character, or '\0' for anything that
	// is not one of the 16 DTMF symbols (event 16 "flash" and the tone events are
	// deliberately NOT digits).
	static char dtmfEventToChar(uint8_t event);

	// The DTMF sink: invoked ONCE per key press, ON THE RECEIVE TASK.
	//
	// Deduplication is the whole difficulty of RFC 4733 and it is done here so no
	// consumer has to. One key press is sent as a BURST of packets that all share
	// the RTP timestamp of the event's START, with a growing `duration`, and the
	// final packet is retransmitted (§2.5.1.2 recommends three times) with E=1. A
	// naive consumer sees one keypress as ~10 callbacks.
	//
	// The rule used: report when the event's RTP timestamp DIFFERS from the last
	// reported one. That fires on the first packet of the burst actually received —
	// which is loss-tolerant, since any packet of the burst will do if the first is
	// dropped — and never fires again for that press. Two presses of the same key
	// carry different timestamps, so a genuine repeat is still reported.
	//   digit    : the keypad character ('0'-'9', '*', '#', 'A'-'D')
	//   durationMs: duration carried by the packet that triggered the report,
	//               converted to ms. Small when reported from the first packet —
	//               it is NOT the total press length, which is not yet known.
	using DtmfSink = std::function<void(char digit, uint16_t durationMs)>;

	// The Sink: callers choose what to do with each received audio frame without
	// RtpReceiver knowing. Invoked once per accepted (PT==0) packet, ON THE
	// RECEIVE TASK, with:
	//   mulaw      : pointer to the raw G.711 µ-law payload bytes (NOT decoded —
	//                voicemail/relay consumers want µ-law as-is on the wire).
	//   n          : number of µ-law bytes (== decoded PCM16 sample count).
	//   timestamp  : the packet's RTP timestamp (8 kHz units) for jitter/ordering.
	//   seq        : the packet's RTP sequence number (for gap detection upstream).
	// CONTRACT: the sink MUST consume synchronously and MUST NOT retain `mulaw`
	// past return (the buffer is reused for the next datagram). To get PCM16, the
	// sink calls RtpReceiver::mulawDecodeBuffer() into its own storage.
	using Sink = std::function<void(const uint8_t* mulaw, size_t n,
		uint32_t timestamp, uint16_t seq)>;

	// ── Pure, platform-independent primitives (host-unit-tested) ────────────────

	// ITU-T G.711 µ-law DECODE of one companded byte → 16-bit linear PCM. Exact
	// inverse of RtpSender::linearToUlaw at the µ-law quantization granularity
	// (µ-law is lossy, so decode(encode(x)) snaps x to the nearest µ-law level).
	static int16_t mulawDecode(uint8_t ulaw);

	// Decode `count` µ-law bytes from `in` into `out` (PCM16). `out` must hold
	// `count` int16_t. No allocation, fully bounds-driven by `count`. Safe no-op
	// on null/empty. Returns the number of samples written.
	static size_t mulawDecodeBuffer(const uint8_t* in, size_t count, int16_t* out);

	// Parse an RTP packet (RFC 3550 §5.1) out of `data`/`len` into `out`.
	// Correctly skips the CSRC list (CC * 4 bytes) and a present header extension
	// (X bit: a 4-byte ext header + a length-prefixed body) so `payload` points at
	// the true media start. Returns false (and leaves `out` untouched) if the
	// buffer is too short, the version is not 2, or the computed payload offset
	// runs past `len`. Used by the receive task AND the host tests.
	static bool parseRtp(const uint8_t* data, size_t len, RtpPacket& out);

	// ── Stream lifecycle (the registrar will drive these from the SIP thread) ───

	RtpReceiver();
	~RtpReceiver();

	// True while a stream is live (socket bound + receive task running). The
	// registrar checks this to enforce the single-stream cap.
	bool isActive() const { return _active.load(std::memory_order_acquire); }

	// The UDP port the receiver is bound on (0 means not started). Lets the
	// caller advertise it in an SDP answer.
	int localPort() const { return _localPort.load(std::memory_order_acquire); }

	// Bind `localPort` and start the receive task, delivering accepted PCMU
	// frames to `sink`. Pass localPort 0 to let the OS pick an ephemeral port
	// (then read it back via localPort()). Returns false if a stream is already
	// active (cap reached) or the socket/task could not be created. On host this
	// is a guarded no-op that still flips _active and records the sink/port so the
	// cap + bind-advertise logic is exercisable in tests.
	bool start(uint16_t localPort, Sink sink);

	// Enable RFC 4733 reception on `pt`, the telephone-event payload type taken
	// from the peer's SDP. Pass kDtmfPayloadTypeUnset to disable. May be called
	// before or after start(); the receive task reads it atomically each packet, so
	// a mid-call re-negotiation is safe. Passing PAYLOAD_TYPE_PCMU is refused — that
	// would shadow audio — and returns false.
	bool setDtmfPayloadType(uint8_t pt, DtmfSink sink);

	// Offer one parsed RTP packet to the RFC 4733 path. Returns true when the
	// packet was a telephone-event on the negotiated payload type and has been
	// consumed (whether or not it produced a digit — a malformed body, a hook
	// flash or a repeat packet of a press already reported all count as
	// consumed); false when it is not telephone-event at all and the caller
	// should go on treating it as audio, or drop it.
	//
	// Public and separate from runLoop() only so host tests can reach it. On a
	// host build start() is a no-op stub that never binds a socket, so every line
	// after recvfrom() is otherwise unreachable off-device — and the press-dedupe
	// (one report per key press, across a burst of packets that may arrive
	// lossily) is exactly the logic worth pinning.
	//
	// Called on the receive task. Touches _lastDtmfTs/_haveLastDtmf, which are
	// owned by that task alone; the sink copy is taken under _slotMutex.
	bool dispatchDtmf(const RtpPacket& pkt);

	// Stop the stream: close the socket (unblocks recvfrom), signal the receive
	// task to exit, clear _active and the sink. Idempotent — safe on an already-
	// idle receiver. Returns true if a stream was actually stopped.
	bool stop();

private:
	// Common, platform-independent slot reset used by stop()/teardown. Caller must
	// hold _slotMutex. Clears the sink and active/port state.
	void clearSlotLocked();

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	static void taskTrampoline(void* arg);
	void runLoop();                       // recvfrom-paced receive loop (Core 0)

	int               _sock = -1;
	// Cross-thread control flags — same ownership model as RtpSender:
	//   _stopRequested : the SIP thread asks the receive task to exit. Closing the
	//                    socket also unblocks a parked recvfrom() immediately.
	//   _taskRunning   : true from just-before-launch until the task's last act.
	//                    The task OWNS its teardown (closes its own socket, clears
	//                    the slot) and clears _taskRunning LAST, so the destructor
	//                    can join on it and start() refuses to overlap a dying task.
	std::atomic<bool> _stopRequested{false};
	std::atomic<bool> _taskRunning{false};
#endif

	std::atomic<bool> _active{false};
	std::atomic<int>  _localPort{0};      // bound RX port (0 = not started)

	// Guards the sink + the start/stop transition so the SIP thread and the
	// receive task never race the slot. Non-recursive (matches RtpSender).
	mutable std::mutex _slotMutex;
	Sink               _sink;             // owner of the live stream's consumer

	// RFC 4733 state. The PT is atomic because the receive task reads it on every
	// packet while the SIP thread may set it at call setup; the sink is guarded by
	// _slotMutex like _sink. _lastDtmfTs/_haveLastDtmf are touched ONLY by the
	// receive task, so they need no synchronisation — but they must be reset by
	// start()/clearSlotLocked(), or the first press of a NEW call whose timestamp
	// happens to match the last press of the previous one would be swallowed.
	std::atomic<uint8_t> _dtmfPt{kDtmfPayloadTypeUnset};
	DtmfSink             _dtmfSink;
	uint32_t             _lastDtmfTs   = 0;
	bool                 _haveLastDtmf = false;
};

#endif
