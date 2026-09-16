#include "RtpReceiver.hpp"

// buildRtpHeader() is reused rather than reimplemented. Two copies of the
// RFC 3550 header layout would be two places to get the big-endian packing
// wrong, and a relay that mis-serialises a header is invisible until a far
// end rejects the stream.
#include "RtpSender.hpp"

#include <cstring>

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
#include <unistd.h>
#include <sys/socket.h>
#include "esp_log.h"
#endif

namespace
{
	// Dedicated server media RX port. Distinct from SIP (5060) and from the
	// RtpSender egress port (5062). The single-stream cap means one fixed RX port
	// is enough and keeps any future SDP answer trivial / firewall-predictable.
	// start(0, ...) overrides this with an OS-chosen ephemeral port.
	constexpr int SERVER_RTP_RX_PORT = 5064;
}

// ── ITU-T G.711 µ-law decode ────────────────────────────────────────────────
// Inverse of RtpSender::linearToUlaw. The companded byte is stored inverted
// (every bit complemented) with the sign in bit 7, the segment/exponent in
// bits 6..4 and the mantissa in bits 3..0. Reconstruct the magnitude as
//   ((mantissa << 1) | 0x21) << exponent  then subtract the 0x84 bias  — the
// standard reference dequantizer (returns the mid-tread level of the µ-law step).
int16_t RtpReceiver::mulawDecode(uint8_t ulaw)
{
	constexpr int BIAS = 0x84;            // 132, matches the encoder bias

	// Undo the encoder's final bit inversion.
	ulaw = static_cast<uint8_t>(~ulaw);

	int sign     = ulaw & 0x80;
	int exponent = (ulaw >> 4) & 0x07;
	int mantissa = ulaw & 0x0F;

	// Reconstruct the quantized magnitude (mid-point of the µ-law step) and remove
	// the bias the encoder added. All math is in `int` so the shifts/sub never
	// overflow a 16-bit type before the final narrowing cast.
	//   step = ((mantissa << 1) | 0x21) << exponent, then minus BIAS  — written
	//   here as ((mantissa << 3) + BIAS) << exponent (algebraically identical for
	//   the µ-law table) minus BIAS, which keeps the same companding levels.
	int magnitude = (((mantissa << 3) + BIAS) << exponent) - BIAS;

	// Negative samples mirror the magnitude about zero. Clamp to int16 range; the
	// reconstruction stays in range, but be defensive against a hand-crafted byte.
	int pcm = (sign != 0) ? -magnitude : magnitude;
	if (pcm > 32767)  pcm = 32767;
	if (pcm < -32768) pcm = -32768;
	return static_cast<int16_t>(pcm);
}

size_t RtpReceiver::mulawDecodeBuffer(const uint8_t* in, size_t count, int16_t* out)
{
	if (in == nullptr || out == nullptr || count == 0)
	{
		return 0;
	}
	for (size_t i = 0; i < count; ++i)
	{
		out[i] = mulawDecode(in[i]);
	}
	return count;
}

// ── RTP header parse (RFC 3550 §5.1), multi-byte fields big-endian on the wire ─
bool RtpReceiver::parseRtp(const uint8_t* data, size_t len, RtpPacket& out)
{
	if (data == nullptr || len < static_cast<size_t>(RTP_HEADER_BYTES))
	{
		return false;   // too short to even hold the fixed 12-byte header
	}

	// Byte 0: V(2) P(1) X(1) CC(4).
	const uint8_t b0      = data[0];
	const uint8_t version = static_cast<uint8_t>((b0 >> 6) & 0x03);
	if (version != 2)
	{
		return false;   // not RTPv2 — drop (could be STUN/RTCP/garbage)
	}
	const bool    padding   = (b0 & 0x20) != 0;
	const bool    extension = (b0 & 0x10) != 0;
	const uint8_t csrcCount = static_cast<uint8_t>(b0 & 0x0F);

	// Byte 1: M(1) PT(7).
	const uint8_t b1     = data[1];
	const bool    marker = (b1 & 0x80) != 0;
	const uint8_t pt     = static_cast<uint8_t>(b1 & 0x7F);

	// The CSRC list follows the fixed header: CC * 4 bytes. Validate before use so
	// a forged CC can't make us read past the datagram.
	size_t offset = static_cast<size_t>(RTP_HEADER_BYTES)
		+ static_cast<size_t>(csrcCount) * 4u;
	if (offset > len)
	{
		return false;
	}

	// Optional header extension (X bit): a 4-byte extension header
	// (16-bit profile id + 16-bit length in 32-bit WORDS) followed by that many
	// words of extension data. Skip the whole thing to reach the media payload.
	if (extension)
	{
		if (offset + 4u > len)
		{
			return false;
		}
		const uint16_t extWords = static_cast<uint16_t>(
			(static_cast<uint16_t>(data[offset + 2]) << 8) | data[offset + 3]);
		const size_t extBytes = 4u + static_cast<size_t>(extWords) * 4u;
		if (offset + extBytes > len)
		{
			return false;
		}
		offset += extBytes;
	}

	size_t payloadLen = len - offset;

	// Padding (P bit): the LAST payload byte is the pad count (including itself);
	// trim it so the consumer never sees pad bytes as audio. Guard against a
	// bogus count that exceeds the remaining payload.
	if (padding && payloadLen > 0)
	{
		const uint8_t pad = data[len - 1];
		if (pad == 0 || static_cast<size_t>(pad) > payloadLen)
		{
			return false;   // malformed padding
		}
		payloadLen -= pad;
	}

	out.version     = version;
	out.marker      = marker;
	out.payloadType = pt;
	out.seq         = static_cast<uint16_t>((static_cast<uint16_t>(data[2]) << 8) | data[3]);
	out.timestamp   = (static_cast<uint32_t>(data[4]) << 24)
		| (static_cast<uint32_t>(data[5]) << 16)
		| (static_cast<uint32_t>(data[6]) << 8)
		|  static_cast<uint32_t>(data[7]);
	out.ssrc        = (static_cast<uint32_t>(data[8]) << 24)
		| (static_cast<uint32_t>(data[9]) << 16)
		| (static_cast<uint32_t>(data[10]) << 8)
		|  static_cast<uint32_t>(data[11]);
	out.payload     = (payloadLen > 0) ? (data + offset) : nullptr;
	out.payloadLen  = payloadLen;
	return true;
}

bool RtpReceiver::parseTelephoneEvent(const uint8_t* payload, size_t len, DtmfEvent& out)
{
	// RFC 4733 §2.3. Exactly four bytes; anything shorter is malformed and anything
	// longer is a multi-event payload whose first event is still at offset 0, so a
	// >= test is correct rather than ==.
	if (payload == nullptr || len < 4) return false;

	out.event    = payload[0];
	out.end      = (payload[1] & 0x80) != 0;
	out.volume   = static_cast<uint8_t>(payload[1] & 0x3F);   // bit 6 is reserved
	out.duration = static_cast<uint16_t>((static_cast<uint16_t>(payload[2]) << 8)
	                                     | static_cast<uint16_t>(payload[3]));
	return true;
}

char RtpReceiver::dtmfEventToChar(uint8_t event)
{
	// RFC 4733 §3.2 table 7. Only the 16 DTMF symbols map to a key; event 16 is
	// hook flash and 17+ are the tone events (dial tone, busy, ringback...), none
	// of which are digits a feature-code parser should ever see.
	if (event <= 9)  return static_cast<char>('0' + event);
	if (event == 10) return '*';
	if (event == 11) return '#';
	if (event >= 12 && event <= 15) return static_cast<char>('A' + (event - 12));
	return '\0';
}

bool RtpReceiver::setDtmfPayloadType(uint8_t pt, DtmfSink sink)
{
	// Refuse to shadow audio. PT 0 is PCMU and is matched first in the receive
	// loop anyway, so accepting it here would silently do nothing — better to say
	// no than to leave a caller believing DTMF is armed.
	if (pt == PAYLOAD_TYPE_PCMU) return false;

	{
		std::lock_guard<std::mutex> lk(_slotMutex);
		_dtmfSink = std::move(sink);
	}
	_dtmfPt.store(pt, std::memory_order_release);
	return true;
}

bool RtpReceiver::setRawSink(RawSink sink)
{
	std::lock_guard<std::mutex> lock(_slotMutex);
	// NOT hasAnyConsumerOrPeerLocked(), despite the identical shape. That
	// predicate answers "has this receiver any reason to be running?"; this
	// asks "was there anything here to disarm?". Substituting it would make
	// setRawSink(nullptr) report success on a send-only leg that has a peer
	// but never had a sink -- claiming to have disarmed something that was
	// never armed.
	if (!sink && !_rawSink)
	{
		return false;   // asked to disarm a receiver that was never armed
	}
	// Publish the flag from inside the lock so the receive task can never see
	// armed==true against a sink that has not been stored yet.
	_rawArmed.store(static_cast<bool>(sink), std::memory_order_release);
	_rawSink = std::move(sink);
	return true;
}

bool RtpReceiver::dispatchRaw(const RtpPacket& pkt)
{
	if (!_rawArmed.load(std::memory_order_acquire))
	{
		return false;   // fast path: an ordinary receiver, no lock taken
	}

	// Copy the handle under the lock and invoke outside it -- same discipline as
	// the audio path, so a slow relay egress never stalls a stop()/start() on
	// the SIP thread (CONTRIBUTING_FIRMWARE rule 3).
	RawSink sink;
	{
		std::lock_guard<std::mutex> lock(_slotMutex);
		sink = _rawSink;
	}
	if (!sink)
	{
		// Disarmed between the flag check and the lock. Report the packet as
		// unclaimed rather than swallowing it, so the normal path still gets it.
		return false;
	}
	sink(pkt);
	return true;
}

bool RtpReceiver::setRawPeer(const sockaddr_in& peer)
{
	if (peer.sin_port == 0 || peer.sin_addr.s_addr == 0)
	{
		// Refuse rather than accept a destination nothing can reach. A relay
		// silently sending into 0.0.0.0:0 looks exactly like a working leg with
		// no audio, which is the most expensive kind of failure to diagnose.
		return false;
	}
	std::lock_guard<std::mutex> lock(_slotMutex);
	_rawPeer = peer;
	_rawPeerSet.store(true, std::memory_order_release);
	return true;
}

// A refusal that DROPPED a packet, as distinct from one that never had a
// destination. Counted on host only; on device it compiles to a plain false
// so the media path carries no bookkeeping it cannot report anywhere.
bool RtpReceiver::countDropAndFail()
{
#if !defined(ESP_PLATFORM) && !defined(ESP32) && !defined(ARDUINO)
	std::lock_guard<std::mutex> lock(_slotMutex);
	++_droppedRawCount;
#endif
	return false;
}

bool RtpReceiver::sendRaw(const RtpPacket& pkt)
{
	if (!_rawPeerSet.load(std::memory_order_acquire)) return false;
	if (pkt.payload == nullptr && pkt.payloadLen != 0)  return countDropAndFail();

	// The datagram must fit the same fixed buffer the receive path uses. A relay
	// never has to grow one: anything larger than MAX_DATAGRAM_BYTES could not
	// have been received through this class in the first place.
	const size_t total = static_cast<size_t>(RTP_HEADER_BYTES) + pkt.payloadLen;
	if (total > static_cast<size_t>(MAX_DATAGRAM_BYTES)) return countDropAndFail();

	uint8_t datagram[MAX_DATAGRAM_BYTES];
	// VERBATIM: the far end's marker, payload type, sequence, timestamp and SSRC
	// all survive. Renumbering here would break the very thing the raw path
	// exists for -- a telephone-event burst is identified by its shared start
	// timestamp, so re-stamping turns one keypress into many or none.
	RtpSender::buildRtpHeader(datagram, pkt.marker, pkt.payloadType,
		pkt.seq, pkt.timestamp, pkt.ssrc);
	if (pkt.payloadLen > 0)
	{
		std::memcpy(datagram + RTP_HEADER_BYTES, pkt.payload, pkt.payloadLen);
	}

	// Copy fd + peer under the lock, send outside it -- same discipline as the
	// audio path, so a slow send cannot stall a stop()/start() on the SIP thread.
	sockaddr_in peer{};
	int         fd = -1;
	{
		std::lock_guard<std::mutex> lock(_slotMutex);
		peer = _rawPeer;
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
		fd = _sock;
#endif
	}

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	if (fd < 0) return false;   // not started: nothing bound to send from
	// A stop() landing between the snapshot and here closes fd and sendto returns
	// EBADF. Harmless, and the same race runLoop()'s own socket snapshot already
	// accepts: the alternative is holding the lock across a syscall.
	const int n = static_cast<int>(sendto(fd, datagram, total, 0,
		reinterpret_cast<const sockaddr*>(&peer), sizeof(peer)));
	return n == static_cast<int>(total);
#else
	// Host: no socket. Record what would have gone on the wire so a test can
	// assert byte fidelity, which is the whole contract of this function.
	(void)fd;
	{
		std::lock_guard<std::mutex> lock(_slotMutex);
		_lastRawDatagram.assign(datagram, datagram + total);
		++_sentRawCount;
	}
	return true;
#endif
}

bool RtpReceiver::dispatchDtmf(const RtpPacket& pkt)
{
	// Split out of runLoop() so it is reachable from a host test. On host,
	// start() is a no-op stub that never binds a socket (see MediaBridge.cpp's
	// note), so everything downstream of recvfrom() is otherwise untestable off
	// the device — and the press-dedupe below is the part most worth pinning.
	const uint8_t dtmfPt = _dtmfPt.load(std::memory_order_acquire);
	if (dtmfPt == kDtmfPayloadTypeUnset || pkt.payloadType != dtmfPt)
	{
		return false;   // not the negotiated telephone-event PT
	}

	DtmfEvent ev;
	if (!parseTelephoneEvent(pkt.payload, pkt.payloadLen, ev))
	{
		return true;    // the right PT but a malformed body: consumed, not audio
	}

	const char digit = dtmfEventToChar(ev.event);
	if (digit == '\0')
	{
		// Hook flash (16) or a tone event (17+): valid RFC 4733, not a keypad
		// symbol. Swallow it rather than passing junk up.
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
		ESP_LOGD("RtpReceiver", "non-digit telephone-event %u ignored",
			static_cast<unsigned>(ev.event));
#endif
		return true;
	}

	// Dedupe on the event's RTP timestamp: every packet of one key press carries
	// the timestamp of the press's START, so a change means a NEW press.
	// Reporting on the first packet SEEN (rather than specifically the first
	// sent, or waiting for E=1) keeps this loss-tolerant — any packet of the
	// burst will do — and still fires exactly once per press.
	if (_haveLastDtmf && pkt.timestamp == _lastDtmfTs)
	{
		return true;    // another packet of a press already reported
	}
	_lastDtmfTs   = pkt.timestamp;
	_haveLastDtmf = true;

	DtmfSink dtmfSink;
	{
		std::lock_guard<std::mutex> lk(_slotMutex);
		dtmfSink = _dtmfSink;
	}
	if (dtmfSink)
	{
		// duration is in 8 kHz units -> ms.
		dtmfSink(digit, static_cast<uint16_t>(ev.duration / 8));
	}
	return true;
}

RtpReceiver::RtpReceiver()
{
	_localPort.store(SERVER_RTP_RX_PORT, std::memory_order_release);
}

RtpReceiver::~RtpReceiver()
{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	// Ask the receive task to stop, then BLOCK until it has fully exited before
	// this object's storage is reclaimed (the task captures `this`). Closing the
	// socket in stop() unblocks a parked recvfrom() immediately; the ~500 ms cap
	// backstops a wedged task. This runs off the SIP hot path.
	stop();
	for (int i = 0; i < 100 && _taskRunning.load(std::memory_order_acquire); ++i)
	{
		vTaskDelay(pdMS_TO_TICKS(5));
	}
#else
	stop();   // host stub: just clears the (no-task) active flag + sink
#endif
}

bool RtpReceiver::hasAnyConsumerOrPeerLocked(const Sink& pending) const
{
	// Three reasons to be running, and they are genuinely different roles:
	//   an audio Sink   -- an ordinary decoded-media consumer;
	//   a raw Sink      -- a relay leg that forwards what it receives;
	//   a raw peer      -- a SEND-ONLY relay leg, which receives nothing and
	//                      needs the socket bound only so sendRaw() can
	//                      source from the port we advertised.
	// `pending` is the Sink about to be installed by start(), which is not in
	// _sink yet.
	return static_cast<bool>(pending)
		|| static_cast<bool>(_rawSink)
		|| _rawPeerSet.load(std::memory_order_acquire);
}

void RtpReceiver::clearSlotLocked()
{
	_sink = nullptr;
	_dtmfSink = nullptr;
	_rawSink = nullptr;
	_rawArmed.store(false, std::memory_order_release);
	// The peer goes with the slot. A pooled receiver handed to a new call must
	// not keep forwarding into the PREVIOUS call's far end.
	_rawPeer = sockaddr_in{};
	_rawPeerSet.store(false, std::memory_order_release);
	_dtmfPt.store(kDtmfPayloadTypeUnset, std::memory_order_release);
	// Reset the dedupe memory with the slot. RFC 4733 keys a press on its RTP
	// timestamp, and timestamps are per-stream: a fresh call starts its own clock
	// at a random offset, so a stale value here could coincide with the new call's
	// first press and swallow it. Cheap insurance against a once-in-2^32 bug that
	// would be unreproducible in the field.
	_lastDtmfTs   = 0;
	_haveLastDtmf = false;
	_active.store(false, std::memory_order_release);
}

// ─────────────────────────────────────────────────────────────────────────────
//  ESP-only: real UDP socket + recvfrom receive task (Core 0)
// ─────────────────────────────────────────────────────────────────────────────
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)

bool RtpReceiver::start(uint16_t localPort, Sink sink)
{
	std::lock_guard<std::mutex> lock(_slotMutex);

	// Single-stream cap: refuse a second concurrent stream, and refuse while a
	// prior task is still tearing itself down (_taskRunning) so the new task never
	// overlaps the old one on the shared socket/slot.
	if (_active.load(std::memory_order_acquire) || _taskRunning.load(std::memory_order_acquire))
	{
		return false;
	}
	// A stream needs SOMEWHERE to deliver, but the audio Sink is no longer the
	// only answer. A raw-relay leg (a SIP trunk) arms setRawSink() instead and
	// has no use for an audio sink at all -- the raw path claims every packet
	// before the payload-type split, so an audio sink passed here would never
	// be invoked. Demanding a no-op one would be a lie in the call signature.
	//
	// _slotMutex is held, so reading _rawSink directly here is safe and sees
	// any setRawSink() that has already returned.
	// A SEND-ONLY relay leg has neither sink: it exists to transmit, and needs
	// start() purely to bind the socket sendRaw() sources from. So an armed raw
	// PEER counts as a reason to be running, exactly as a sink does.
	if (!hasAnyConsumerOrPeerLocked(sink))
	{
		ESP_LOGE("RtpReceiver", "start() called with no sink and no raw peer");
		return false;
	}

	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
	{
		ESP_LOGE("RtpReceiver", "socket() failed");
		return false;
	}

	// A bounded recv timeout so the loop can observe _stopRequested even if the
	// socket close somehow does not unblock recvfrom() on this lwIP build. Mirrors
	// UdpServer's 500 ms SO_RCVTIMEO pattern.
	struct timeval tv;
	tv.tv_sec  = 0;
	tv.tv_usec = 500000;   // 500 ms
	if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0)
	{
		ESP_LOGW("RtpReceiver", "SO_RCVTIMEO setsockopt failed (non-fatal)");
	}

	sockaddr_in local{};
	local.sin_family      = AF_INET;
	local.sin_addr.s_addr = htonl(INADDR_ANY);
	local.sin_port        = htons(localPort);   // 0 → OS picks an ephemeral port
	if (bind(sock, reinterpret_cast<sockaddr*>(&local), sizeof(local)) < 0)
	{
		ESP_LOGE("RtpReceiver", "bind(%u) failed", static_cast<unsigned>(localPort));
		close(sock);
		return false;
	}

	// Read back the actually-bound port (matters when localPort==0 ephemeral).
	uint16_t boundPort = localPort;
	sockaddr_in bound{};
	socklen_t   boundLen = sizeof(bound);
	if (getsockname(sock, reinterpret_cast<sockaddr*>(&bound), &boundLen) == 0)
	{
		boundPort = ntohs(bound.sin_port);
	}

	_sock = sock;
	_sink = std::move(sink);
	_localPort.store(static_cast<int>(boundPort), std::memory_order_release);
	_stopRequested.store(false, std::memory_order_release);
	// Mark running BEFORE the task launches so a stop() racing right behind us
	// can't clear the slot before the task exists. The task clears this LAST.
	_taskRunning.store(true, std::memory_order_release);
	_active.store(true, std::memory_order_release);

	// Issue #49 sibling (mirrors RtpSender): the display build reserves Core 1 for
	// LVGL and runs SIP on Core 0; the receive task joins SIP on Core 0. Priority 6
	// (one above the udp_receiver/SIP task at 5) so inbound media is not starved by
	// signaling bursts. Handle is nullptr: the task self-manages its lifecycle via
	// _stopRequested / _taskRunning, so we never store (and race on) a TaskHandle_t.
	BaseType_t ok = xTaskCreatePinnedToCore(
		&RtpReceiver::taskTrampoline,
		"rtp_media_rx",
		6144,   // headroom for lwIP recvfrom() + sink callback (decode is in-place)
		this,
		6,
		nullptr,
		0 /* Core 0 */);

	if (ok != pdPASS)
	{
		ESP_LOGE("RtpReceiver", "xTaskCreatePinnedToCore failed");
		close(_sock);
		_sock = -1;
		clearSlotLocked();
		_taskRunning.store(false, std::memory_order_release);
		return false;
	}

	ESP_LOGI("RtpReceiver", "Media RX started on port %d",
		_localPort.load(std::memory_order_acquire));
	return true;
}

bool RtpReceiver::stop()
{
	std::lock_guard<std::mutex> lock(_slotMutex);
	if (!_active.load(std::memory_order_acquire))
	{
		return false;
	}

	// NON-BLOCKING request: ask the task to exit and proactively close the socket
	// to unblock a parked recvfrom() immediately. The task owns the final slot
	// clear in runLoop() so we do NOT join here (matches RtpSender::stop(): the
	// registrar calls this under its big handler mutex and must not block on the
	// media task). The slot stays _active until the task actually exits, so the
	// single-stream cap remains correct in the brief teardown window.
	_stopRequested.store(true, std::memory_order_release);
	if (_sock >= 0)
	{
		// shutdown()+close() race the task's own close, but the task re-checks
		// `_sock == sock` before nulling, so a double close on the same fd cannot
		// land on a fd we reused (start() is gated by _taskRunning).
		shutdown(_sock, SHUT_RDWR);
	}
	ESP_LOGI("RtpReceiver", "Media RX stop requested");
	return true;
}

void RtpReceiver::taskTrampoline(void* arg)
{
	auto* self = static_cast<RtpReceiver*>(arg);
	self->runLoop();   // closes the socket + clears the slot under _slotMutex
	// Clearing _taskRunning is the LAST access to `self`: after this the destructor
	// may observe the task as gone and allow the object to be destroyed.
	self->_taskRunning.store(false, std::memory_order_release);
	vTaskDelete(nullptr);
}

void RtpReceiver::runLoop()
{
	// Snapshot the immutable per-stream socket ONCE under the lock. It is written
	// only in start() before this task is created and is never mutated for the
	// life of the stream, so working off a local removes the cross-thread read of
	// _sock the hot loop would otherwise do every datagram.
	int sock;
	{
		std::lock_guard<std::mutex> lock(_slotMutex);
		sock = _sock;
	}

	// One fixed receive buffer reused every datagram — no per-packet heap. PCM16
	// decode, when a consumer wants it, is the sink's responsibility into its own
	// storage; here we only ever expose the raw µ-law payload.
	uint8_t buffer[RtpReceiver::MAX_DATAGRAM_BYTES];

	// Basic sequence-gap tolerance (do NOT over-engineer a full jitter buffer):
	// track the last accepted seq purely to LOG gaps/reorders for diagnostics. We
	// still deliver every in-PT packet to the sink in arrival order; a real jitter
	// buffer / reorder window belongs in the consumer (voicemail can store as-is;
	// the B2BUA bridge re-paces on its own egress clock).
	bool     haveLastSeq = false;
	uint16_t lastSeq     = 0;

	while (!_stopRequested.load(std::memory_order_acquire))
	{
		if (sock < 0)
		{
			break;
		}

		sockaddr_in from{};
		socklen_t   fromLen = sizeof(from);
		int n = static_cast<int>(recvfrom(sock, buffer, sizeof(buffer), 0,
			reinterpret_cast<sockaddr*>(&from), &fromLen));
		if (n <= 0)
		{
			// Timeout (EAGAIN) or socket closed by stop(): re-check the stop flag.
			continue;
		}

		RtpReceiver::RtpPacket pkt;
		if (!parseRtp(buffer, static_cast<size_t>(n), pkt))
		{
			continue;   // not a valid RTPv2 packet — drop silently
		}

		// RAW RELAY, when armed, owns the whole packet path: a trunk leg forwards
		// bytes rather than interpreting them, so this deliberately runs BEFORE
		// the payload-type split below and skips the audio sink, the RFC 4733
		// decode and the gap diagnostics. See setRawSink() for why that matters.
		if (dispatchRaw(pkt))
		{
			continue;
		}
		if (pkt.payloadType != RtpReceiver::PAYLOAD_TYPE_PCMU)
		{
			// Not audio. It may still be an RFC 4733 named event on the dynamic PT
			// the peer advertised at call setup — that is the ONLY way DTMF reaches
			// the board on a server-terminated leg, since an ordinary call's RTP is
			// peer-to-peer and never passes through here at all.
			//
			// Anything dispatchDtmf() does not claim (comfort noise, a codec we do
			// not speak) is dropped gracefully — the audio consumers only handle
			// µ-law.
			dispatchDtmf(pkt);
			continue;
		}
		if (pkt.payload == nullptr || pkt.payloadLen == 0)
		{
			continue;   // header-only / empty packet
		}

		// Sequence-gap diagnostics (tolerant: never drops, just notes the gap).
		if (haveLastSeq)
		{
			uint16_t expected = static_cast<uint16_t>(lastSeq + 1);
			if (pkt.seq != expected)
			{
				ESP_LOGD("RtpReceiver", "seq gap: expected %u got %u",
					static_cast<unsigned>(expected), static_cast<unsigned>(pkt.seq));
			}
		}
		lastSeq     = pkt.seq;
		haveLastSeq = true;

		// Hand the RAW µ-law payload to the consumer. Take the sink under the slot
		// lock just long enough to copy the std::function handle, then invoke it
		// OUTSIDE the lock so a slow consumer (e.g. a flash write) never stalls a
		// stop()/start() on the SIP thread (CONTRIBUTING_FIRMWARE rule 3).
		Sink sink;
		{
			std::lock_guard<std::mutex> lock(_slotMutex);
			sink = _sink;
		}
		if (sink)
		{
			sink(pkt.payload, pkt.payloadLen, pkt.timestamp, pkt.seq);
		}
	}

	// This task OWNS its socket: close the local fd and clear the shared slot so a
	// new stream can start. The start()/_taskRunning guard guarantees no start()
	// has re-pointed _sock under us; the `_sock == sock` check is belt-and-braces.
	{
		std::lock_guard<std::mutex> lock(_slotMutex);
		if (sock >= 0)
		{
			close(sock);
		}
		if (_sock == sock)
		{
			_sock = -1;
		}
		clearSlotLocked();
	}
	ESP_LOGI("RtpReceiver", "Media RX stopped");
}

#else   // ── Host stubs: keep the cap / bind-advertise logic testable, no I/O ──

bool RtpReceiver::start(uint16_t localPort, Sink sink)
{
	std::lock_guard<std::mutex> lock(_slotMutex);
	if (_active.load(std::memory_order_acquire))
	{
		return false;   // single-stream cap still enforced on host (for tests)
	}
	// Mirrors the ESP guard: a raw-relay leg (a SIP trunk) has no audio sink by
	// design, so only the total absence of a consumer is refused. Keeping the
	// two arms in step matters -- this stub is the ONLY start() the host tests
	// ever call, so a divergence here means the tests pin behaviour the device
	// does not have.
	// Mirrors the ESP guard, including the send-only relay leg. This stub is
	// the only start() the host tests can reach, so a divergence here pins
	// behaviour the device does not have.
	if (!hasAnyConsumerOrPeerLocked(sink))
	{
		return false;
	}
	_sink = std::move(sink);
	// On host there is no real bind; a non-zero request is echoed back so the
	// advertise path is exercisable, and 0 stays 0 (no OS to pick a port).
	if (localPort != 0)
	{
		_localPort.store(static_cast<int>(localPort), std::memory_order_release);
	}
	_active.store(true, std::memory_order_release);
	return true;
}

bool RtpReceiver::stop()
{
	std::lock_guard<std::mutex> lock(_slotMutex);
	if (!_active.load(std::memory_order_acquire))
	{
		return false;
	}
	clearSlotLocked();
	return true;
}

#endif

#if !defined(ESP_PLATFORM) && !defined(ESP32) && !defined(ARDUINO)
size_t RtpReceiver::sentRawCount() const
{
	std::lock_guard<std::mutex> lock(_slotMutex);
	return _sentRawCount;
}

size_t RtpReceiver::droppedRawCount() const
{
	std::lock_guard<std::mutex> lock(_slotMutex);
	return _droppedRawCount;
}

const std::vector<uint8_t>& RtpReceiver::lastRawDatagram() const
{
	// Returned by reference deliberately: a test compares it against an expected
	// byte sequence immediately and copying a datagram per assertion would only
	// obscure that. Not thread-safe to hold across another sendRaw(), which no
	// single-threaded host test does.
	std::lock_guard<std::mutex> lock(_slotMutex);
	return _lastRawDatagram;
}
#endif
