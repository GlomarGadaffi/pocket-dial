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
#include <vector>

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
	//
	// Issue #284: raw function pointer + context, not std::function. This is
	// copied under _slotMutex and invoked on every reported digit, on the RTP
	// receive task -- a std::function whose installed closure exceeds the
	// libstdc++ SBO (8 bytes on this target) heap-allocates on every copy,
	// which is exactly what MediaBridge's old `[legCallId, sink]` installer
	// did (a std::string + a std::function, 40 bytes). A raw pointer pair is
	// always a trivial, allocation-free copy, by construction, regardless of
	// what any future installer wants to capture. Same shape as HoldMusic's
	// tap (HoldMusic.hpp:178).
	using DtmfSink = void (*)(void* ctx, char digit, uint16_t durationMs);

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

	// The RawSink: a B2BUA relay leg's egress. Invoked once per well-formed
	// RTPv2 datagram, ON THE RECEIVE TASK, with the packet exactly as it
	// arrived -- payload type, sequence, timestamp and marker intact, payload
	// undecoded.
	//
	// WHY THIS IS SEPARATE FROM Sink. A trunk leg must forward what it
	// receives, not interpret it. Sink hands out audio only (PT 0), and
	// runLoop() drops every other payload type after offering it to the RFC
	// 4733 path -- so on a relay leg the carrier's telephone-event packets,
	// comfort noise and any codec we do not speak would all be destroyed, and
	// DTMF would never cross the trunk at all. RawSink is the escape hatch:
	// it sees everything.
	//
	// CONTRACT: as Sink -- consume synchronously, do NOT retain pkt.payload
	// past return (the datagram buffer is reused for the next packet).
	//
	// Issue #284: raw function pointer + context, not std::function -- same
	// reasoning as DtmfSink above. No installer exists on main yet (the #164
	// trunk wiring is what will call setRawSink()), so this is the cheapest
	// point to fix the type: every future installer inherits an
	// allocation-free copy instead of depending on a capture-size convention
	// nobody enforces.
	using RawSink = void (*)(void* ctx, const RtpPacket& pkt);

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
	//
	// `sink` may be null IF a raw sink is already armed (setRawSink) -- a relay
	// leg has no audio consumer by design. With neither, start() refuses: a
	// bound socket and a running task delivering nowhere is a leak, not a
	// stream.
	bool start(uint16_t localPort, Sink sink);

	// Enable RFC 4733 reception on `pt`, the telephone-event payload type taken
	// from the peer's SDP. Pass kDtmfPayloadTypeUnset to disable. May be called
	// before or after start(); the receive task reads it atomically each packet, so
	// a mid-call re-negotiation is safe. Passing PAYLOAD_TYPE_PCMU is refused — that
	// would shadow audio — and returns false.
	bool setDtmfPayloadType(uint8_t pt, DtmfSink sink, void* ctx = nullptr);

	// Arm RAW RELAY for this stream. While a raw sink is set, EVERY
	// well-formed RTPv2 packet goes to it intact and nothing else runs: no
	// audio Sink, no RFC 4733 decode, no sequence-gap diagnostics.
	//
	// The exclusivity is the point, not an optimisation. A relay leg that
	// also decoded DTMF would hand the carrier's IVR keypresses to whatever
	// the local digit consumer is -- on this PBX, the star-code feature
	// parser -- so a caller navigating "press 1 for billing" would trip a
	// local feature code instead. Making raw mode take over the packet path
	// means that cannot be wired up by accident: there is no state in which
	// one receiver both relays and interprets.
	//
	// Pass nullptr to disarm and return the stream to normal audio handling.
	// May be called before or after start(). Returns false only when asked to
	// disarm a receiver that had no raw sink armed.
	bool setRawSink(RawSink sink, void* ctx = nullptr);

	// Offer one parsed packet to the raw-relay path. Returns true when a raw
	// sink was armed and consumed it, in which case the caller must not
	// process the packet further. Public for the same reason dispatchDtmf()
	// is: start() is a no-op stub on host builds, so everything downstream of
	// recvfrom() would otherwise be unreachable off-device.
	bool dispatchRaw(const RtpPacket& pkt);

	// Point this receiver's socket at a peer, so sendRaw() can transmit from
	// it. May be called before or after start().
	//
	// WHY THE EGRESS LIVES ON THE RECEIVER and not on RtpSender, which is the
	// obvious place to look for it:
	//
	//   1. SYMMETRIC RTP, which NAT-latching carriers require. This socket is
	//      bound to the port we advertised in SDP, so media leaves from exactly
	//      the address the far end was told to expect. RtpSender binds its own
	//      FIXED port (SERVER_RTP_PORT 5062), so sending from it would advertise
	//      one port and source from another.
	//   2. ONE SOCKET PER LEG. A relay needs two independent legs; two RtpSenders
	//      would contend for that single 5062 bind and the loser falls back to an
	//      ephemeral port with only a warning -- one-way audio, diagnosable only
	//      with a capture.
	//   3. NO FrameProvider ANYWHERE ON A RELAY LEG, so a provider's own SSRC can
	//      never interleave with forwarded packets on one stream. That hazard is
	//      removed by construction rather than by a documented convention.
	bool setRawPeer(const sockaddr_in& peer);

	// Forward one packet VERBATIM: original marker, payload type, sequence,
	// timestamp and SSRC, payload bytes untouched. This is the egress half of
	// setRawSink() and the reason a trunk can carry DTMF at all -- re-stamping a
	// telephone-event packet as PCMU, which is all RtpSender's FrameProvider can
	// do, destroys it.
	//
	// Returns false if no peer is set, the stream is not started, or the packet
	// does not fit MAX_DATAGRAM_BYTES. Safe to call from the receive task: the
	// socket and peer are copied under _slotMutex and the sendto happens outside
	// it, so a slow send cannot stall a stop()/start() on the SIP thread.
	bool sendRaw(const RtpPacket& pkt);

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

	// ── Host-only test seam ─────────────────────────────────────────────────
	//
	// On host there is no socket, so sendRaw() records the datagram it WOULD
	// have transmitted instead. That is the only way to assert byte fidelity of
	// a forwarded packet off-device, and byte fidelity is the entire point of
	// this path -- a relay that quietly renumbers or re-stamps produces a stream
	// the far end cannot reassemble.
	//
	// Absent on device: it would be dead weight on the media path, and there is
	// nothing off-target to read it.
	#if !defined(ESP_PLATFORM) && !defined(ESP32) && !defined(ARDUINO)
	size_t                      sentRawCount() const;
	// Packets sendRaw() REFUSED. Counted so a test can prove a drop happened
	// rather than only observing a false return -- "returned false" and
	// "dropped a packet" are different claims.
	size_t                      droppedRawCount() const;
	const std::vector<uint8_t>& lastRawDatagram() const;
	#endif

private:
	// Common, platform-independent slot reset used by stop()/teardown. Caller must
	// hold _slotMutex. Clears the sink and active/port state.
	void clearSlotLocked();

	// The ONE place that answers "does this receiver have a reason to be
	// running?". Used by both arms of start()'s #if.
	//
	// It exists because that question has been answered wrong twice in this
	// class: once when a raw-relay receiver with no audio Sink was refused,
	// and again when a SEND-ONLY leg with no sink at all -- only a peer, and
	// needing start() purely to bind the socket sendRaw() transmits from --
	// was refused. Both times the fix had to be applied to the ESP arm AND the
	// host stub, and the host stub is the only start() the tests can reach, so
	// a divergence pins behaviour the device does not have. A fourth reason
	// goes here, once.
	//
	// Caller holds _slotMutex.
	bool hasAnyConsumerOrPeerLocked(const Sink& pending) const;

	// Refuse, and on host record that a packet was dropped. See the impl.
	bool countDropAndFail();

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
	DtmfSink             _dtmfSink = nullptr;
	void*                _dtmfSinkCtx = nullptr;

	// Raw relay (B2BUA trunk leg). The sink is guarded by _slotMutex like
	// _sink; the atomic flag lets the receive task skip the lock entirely on
	// the common non-relay path -- one acquire-load per packet, not a mutex.
	std::atomic<bool> _rawArmed{false};
	RawSink           _rawSink = nullptr;
	void*             _rawSinkCtx = nullptr;

	// Raw egress. The peer is guarded by _slotMutex like the sinks; the atomic
	// flag lets sendRaw() reject early without taking the lock.
	std::atomic<bool> _rawPeerSet{false};
	sockaddr_in       _rawPeer{};

#if !defined(ESP_PLATFORM) && !defined(ESP32) && !defined(ARDUINO)
	// Host-only record of what sendRaw() would have transmitted. Guarded by
	// _slotMutex like everything else in the slot. See the accessors above.
	std::vector<uint8_t> _lastRawDatagram;
	size_t               _sentRawCount = 0;
	size_t               _droppedRawCount = 0;
#endif
	uint32_t             _lastDtmfTs   = 0;
	bool                 _haveLastDtmf = false;
};

#endif
