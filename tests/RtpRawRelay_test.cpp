// RtpRawRelay_test.cpp — issue #164: the raw egress a SIP trunk's B2BUA leg
// relays through.
//
// A trunk leg must FORWARD what it receives rather than interpret it, and
// before this existed RtpReceiver could do neither. runLoop() dropped every
// packet that was not PCMU and was not claimed by the RFC 4733 path
// (RtpReceiver.cpp, the payloadType != PAYLOAD_TYPE_PCMU branch), and `Sink`
// handed out decoded µ-law only with no access to the original packet — so a
// carrier's telephone-event packets, its comfort noise and any codec we do not
// speak were all destroyed on the way through, and DTMF could never cross a
// trunk at all.
//
// Two properties are worth pinning here, and the second is a safety property
// rather than a feature:
//
//   1. FIDELITY — what the sink sees is the packet as it arrived. A relay that
//      quietly loses the marker bit, renumbers the sequence or truncates the
//      payload produces a stream the far end cannot reassemble.
//
//   2. EXCLUSIVITY — an armed relay leg claims the packet, so nothing else on
//      the receive path runs. This is what makes it structurally impossible for
//      a trunk leg to also decode DTMF into the LOCAL star-code feature parser,
//      which would turn a caller pressing "1" at a carrier IVR into a local
//      feature code. The guarantee is "there is no state in which one receiver
//      both relays and interprets", so the test arms BOTH and proves the raw
//      path takes it.
//
// Everything here runs against dispatchRaw() directly. On a host build start()
// is a no-op stub that never binds a socket, so the packet path downstream of
// recvfrom() is otherwise unreachable off-device — the same reason
// dispatchDtmf() is public (see Rfc4733Dtmf_test.cpp).

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <vector>

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#else
#include <arpa/inet.h>
#endif

#include "RtpReceiver.hpp"

namespace
{
	constexpr uint8_t kDtmfPt = 101;   // what nearly every phone offers
	constexpr uint8_t kOpusPt = 111;   // "a codec we do not speak"

	// A parsed packet as runLoop() hands it to dispatchRaw().
	RtpReceiver::RtpPacket packet(uint8_t pt, uint16_t seq, uint32_t ts,
		const uint8_t* payload, size_t len, bool marker = false)
	{
		RtpReceiver::RtpPacket pkt{};
		pkt.version     = 2;
		pkt.marker      = marker;
		pkt.payloadType = pt;
		pkt.seq         = seq;
		pkt.timestamp   = ts;
		pkt.ssrc        = 0xDEADBEEF;
		pkt.payload     = payload;
		pkt.payloadLen  = len;
		return pkt;
	}

	// What a relay egress would have to capture to forward the packet onward.
	struct Captured
	{
		int                  calls = 0;
		uint8_t              pt    = 0;
		uint16_t             seq   = 0;
		uint32_t             ts    = 0;
		uint32_t             ssrc  = 0;
		bool                 marker = false;
		std::vector<uint8_t> payload;
	};

	RtpReceiver::RawSink capture(Captured& out)
	{
		return [&out](const RtpReceiver::RtpPacket& pkt) {
			++out.calls;
			out.pt     = pkt.payloadType;
			out.seq    = pkt.seq;
			out.ts     = pkt.timestamp;
			out.ssrc   = pkt.ssrc;
			out.marker = pkt.marker;
			out.payload.assign(pkt.payload, pkt.payload + pkt.payloadLen);
		};
	}

	// One RFC 4733 event body (event code, E bit, volume, duration) — the thing
	// that must reach a carrier intact instead of being decoded locally.
	struct EventBody { uint8_t b[4]; };

	EventBody eventBody(uint8_t event, bool end, uint16_t duration)
	{
		EventBody e{};
		e.b[0] = event;
		e.b[1] = static_cast<uint8_t>((end ? 0x80 : 0x00) | 0x0A);   // volume 10
		e.b[2] = static_cast<uint8_t>(duration >> 8);
		e.b[3] = static_cast<uint8_t>(duration & 0xFF);
		return e;
	}
}

// ── Default-safe ─────────────────────────────────────────────────────────────

// The property the whole trunk design leans on: a receiver nobody armed claims
// nothing. Every existing call site (MediaBridge, ConferenceRoom) gets this
// behaviour without being touched.
TEST(RtpRawRelay, UnarmedReceiverClaimsNothing)
{
	RtpReceiver rx;
	const uint8_t audio[4] = {1, 2, 3, 4};
	EXPECT_FALSE(rx.dispatchRaw(packet(RtpReceiver::PAYLOAD_TYPE_PCMU, 1, 160, audio, sizeof(audio))));
}

// Disarming something that was never armed is a no-op, reported as such rather
// than as success — so a caller cannot read "true" as "relay is now off" when
// it was never on.
TEST(RtpRawRelay, DisarmingAnUnarmedReceiverReportsNothingToDo)
{
	RtpReceiver rx;
	EXPECT_FALSE(rx.setRawSink(nullptr));
}

// ── Fidelity ─────────────────────────────────────────────────────────────────

// Every header field a relay has to preserve, plus the payload bytes. Written
// as one test over a packet with all fields distinct and non-default, so a
// mix-up between seq and timestamp (both integers, easy to transpose in a
// forwarding path) fails here rather than on the wire.
TEST(RtpRawRelay, ArmedSinkSeesThePacketExactlyAsItArrived)
{
	RtpReceiver rx;
	Captured got;
	ASSERT_TRUE(rx.setRawSink(capture(got)));

	const uint8_t payload[] = {0xFF, 0x7F, 0x00, 0x80, 0x2A};
	ASSERT_TRUE(rx.dispatchRaw(
		packet(RtpReceiver::PAYLOAD_TYPE_PCMU, 4242, 0xCAFEBABE, payload, sizeof(payload),
			/*marker=*/true)));

	EXPECT_EQ(got.calls, 1);
	EXPECT_EQ(got.pt, RtpReceiver::PAYLOAD_TYPE_PCMU);
	EXPECT_EQ(got.seq, 4242);
	EXPECT_EQ(got.ts, 0xCAFEBABEu);
	EXPECT_EQ(got.ssrc, 0xDEADBEEFu);
	EXPECT_TRUE(got.marker);
	ASSERT_EQ(got.payload.size(), sizeof(payload));
	EXPECT_EQ(std::memcmp(got.payload.data(), payload, sizeof(payload)), 0);
}

// The whole point of relaying rather than decoding: payload types the board has
// no opinion about still cross. Before this path existed runLoop() dropped both
// of these outright.
TEST(RtpRawRelay, RelaysPayloadTypesTheBoardCannotDecode)
{
	RtpReceiver rx;
	Captured got;
	ASSERT_TRUE(rx.setRawSink(capture(got)));

	const uint8_t opus[3] = {0x11, 0x22, 0x33};
	EXPECT_TRUE(rx.dispatchRaw(packet(kOpusPt, 1, 160, opus, sizeof(opus))));
	EXPECT_EQ(got.calls, 1);
	EXPECT_EQ(got.pt, kOpusPt);

	const EventBody ev = eventBody(1, false, 160);
	EXPECT_TRUE(rx.dispatchRaw(packet(kDtmfPt, 2, 320, ev.b, sizeof(ev.b))));
	EXPECT_EQ(got.calls, 2);
	EXPECT_EQ(got.pt, kDtmfPt);
}

// Relay is per-packet, not one-shot: a stream is thousands of these.
TEST(RtpRawRelay, EveryPacketOfAStreamIsRelayed)
{
	RtpReceiver rx;
	Captured got;
	ASSERT_TRUE(rx.setRawSink(capture(got)));

	const uint8_t frame[160] = {};
	for (uint16_t i = 0; i < 50; ++i)
	{
		ASSERT_TRUE(rx.dispatchRaw(packet(RtpReceiver::PAYLOAD_TYPE_PCMU,
			static_cast<uint16_t>(1000 + i), 160u * i, frame, sizeof(frame))));
	}
	EXPECT_EQ(got.calls, 50);
	EXPECT_EQ(got.seq, 1049);
}

// ── Exclusivity: the safety property ─────────────────────────────────────────

// The one that matters. A trunk leg has RFC 4733 reception armed on the same
// receiver (a real possibility, since the same class serves both roles and a
// future caller could arm both) — the raw path must still claim the packet, so
// runLoop()'s `if (dispatchRaw(pkt)) continue;` skips dispatchDtmf() entirely
// and the digit never reaches the local star-code parser.
//
// Asserting on dispatchRaw()'s RETURN, not just on the sink firing, is the
// point: the return is what runLoop() branches on, so it is the actual contract
// that keeps the two paths apart.
TEST(RtpRawRelay, ClaimsTelephoneEventEvenWhenDtmfIsAlsoArmed)
{
	RtpReceiver rx;

	int localDigits = 0;
	ASSERT_TRUE(rx.setDtmfPayloadType(kDtmfPt,
		[&localDigits](char, uint16_t) { ++localDigits; }));

	Captured got;
	ASSERT_TRUE(rx.setRawSink(capture(got)));

	const EventBody ev = eventBody(1, false, 160);   // the digit '1'
	EXPECT_TRUE(rx.dispatchRaw(packet(kDtmfPt, 7, 900, ev.b, sizeof(ev.b))));

	// Claimed by the relay, so runLoop() never offers it to the DTMF path.
	EXPECT_EQ(got.calls, 1);
	EXPECT_EQ(got.pt, kDtmfPt);

	// And had it been offered anyway, this is the local consumer it would have
	// reached — the star-code feature parser's entry point on a real leg.
	EXPECT_EQ(localDigits, 0);
}

// The inverse, so the previous test cannot pass for the wrong reason: with NO
// raw sink armed, that identical packet does reach the DTMF path. If this ever
// goes red the exclusivity test above is vacuous.
TEST(RtpRawRelay, WithoutARawSinkTheSamePacketStillReachesTheDtmfPath)
{
	RtpReceiver rx;

	int localDigits = 0;
	char seen = '\0';
	ASSERT_TRUE(rx.setDtmfPayloadType(kDtmfPt,
		[&](char d, uint16_t) { ++localDigits; seen = d; }));

	const EventBody ev = eventBody(1, false, 160);
	const auto pkt = packet(kDtmfPt, 7, 900, ev.b, sizeof(ev.b));

	EXPECT_FALSE(rx.dispatchRaw(pkt));   // nothing armed — unclaimed
	EXPECT_TRUE(rx.dispatchDtmf(pkt));   // so the ordinary path takes it
	EXPECT_EQ(localDigits, 1);
	EXPECT_EQ(seen, '1');
}

// ── Lifecycle ────────────────────────────────────────────────────────────────

// Disarming returns the receiver to ordinary handling. A trunk leg torn down
// and its receiver reused as a handset leg must not keep relaying.
TEST(RtpRawRelay, DisarmingRestoresOrdinaryHandling)
{
	RtpReceiver rx;
	Captured got;
	ASSERT_TRUE(rx.setRawSink(capture(got)));

	const uint8_t frame[4] = {9, 9, 9, 9};
	ASSERT_TRUE(rx.dispatchRaw(packet(RtpReceiver::PAYLOAD_TYPE_PCMU, 1, 160, frame, sizeof(frame))));
	EXPECT_EQ(got.calls, 1);

	ASSERT_TRUE(rx.setRawSink(nullptr));
	EXPECT_FALSE(rx.dispatchRaw(packet(RtpReceiver::PAYLOAD_TYPE_PCMU, 2, 320, frame, sizeof(frame))));
	EXPECT_EQ(got.calls, 1);   // not called again
}

// A relay leg starts with NO audio sink. Before setRawSink() existed start()
// refused a null sink outright, which would have forced a trunk to pass a no-op
// audio consumer that the raw path guarantees is never called.
TEST(RtpRawRelay, ARelayLegStartsWithNoAudioSink)
{
	RtpReceiver rx;
	Captured got;
	ASSERT_TRUE(rx.setRawSink(capture(got)));
	EXPECT_TRUE(rx.start(0, nullptr)) << "a raw sink is a consumer; start must accept it";
	EXPECT_TRUE(rx.stop());
}

// With neither sink there is nothing to deliver to, and start() must still say no.
TEST(RtpRawRelay, StartStillRefusesWhenThereIsNoSinkAtAll)
{
	RtpReceiver rx;
	EXPECT_FALSE(rx.start(0, nullptr));
}

// stop() clears the raw sink with the rest of the slot. Without this a pooled
// receiver handed to a new call would go on relaying into the PREVIOUS call's
// egress — the same class of bug clearSlotLocked() already guards against for
// the audio sink and the RFC 4733 dedupe state.
TEST(RtpRawRelay, StopClearsTheRawSinkWithTheSlot)
{
	RtpReceiver rx;
	Captured got;
	ASSERT_TRUE(rx.setRawSink(capture(got)));
	ASSERT_TRUE(rx.start(0, nullptr));   // host stub: flips _active, binds nothing

	ASSERT_TRUE(rx.stop());

	const uint8_t frame[4] = {1, 2, 3, 4};
	EXPECT_FALSE(rx.dispatchRaw(packet(RtpReceiver::PAYLOAD_TYPE_PCMU, 1, 160, frame, sizeof(frame))));
	EXPECT_EQ(got.calls, 0);
}

// ── The EGRESS half ──────────────────────────────────────────────────────────
//
// setRawSink() (above) was shipped in #250 with nothing that could put a
// received packet back on the wire intact. RtpSender only has FrameProvider, a
// pull model that stamps PT 0 with its own seq/ts, so a forwarded
// telephone-event packet would have been re-stamped as PCMU -- destroying the
// exact thing the raw path exists to carry. Found in review by a second reader,
// not by any test, which is why the fidelity assertion below is byte-exact
// rather than field-by-field.
//
// The egress lives on RtpReceiver, not RtpSender, for three reasons worth
// restating where the tests are: this socket is bound to the port advertised in
// SDP, so media leaves from where the far end expects it (symmetric RTP, which
// NAT-latching carriers require); RtpSender binds a single fixed 5062 so two
// relay legs would contend for it; and with no FrameProvider anywhere on a
// relay leg, a provider's own SSRC can never interleave with forwarded packets.

namespace
{
	sockaddr_in peerAt(const char* ip, uint16_t port)
	{
		sockaddr_in a{};
		a.sin_family = AF_INET;
		a.sin_addr.s_addr = inet_addr(ip);
		a.sin_port = htons(port);
		return a;
	}
}

TEST(RtpRawEgress, RefusedWithoutAPeer)
{
	RtpReceiver rx;
	const uint8_t body[4] = {1, 2, 3, 4};
	EXPECT_FALSE(rx.sendRaw(packet(RtpReceiver::PAYLOAD_TYPE_PCMU, 1, 160, body, sizeof(body))))
		<< "no destination configured -- must refuse rather than send nowhere";
	EXPECT_EQ(rx.sentRawCount(), 0u);
}

// An unreachable destination is refused at configuration time. A relay quietly
// sending into 0.0.0.0:0 looks identical to a working leg with no audio.
TEST(RtpRawEgress, AnUnusablePeerIsRefused)
{
	RtpReceiver rx;
	EXPECT_FALSE(rx.setRawPeer(peerAt("0.0.0.0", 4000))) << "unspecified address";
	EXPECT_FALSE(rx.setRawPeer(peerAt("203.0.113.9", 0))) << "port 0";
	EXPECT_TRUE(rx.setRawPeer(peerAt("203.0.113.9", 4000)));
}

// The whole contract, asserted byte-for-byte against a hand-built header. A
// relay that renumbers or re-stamps produces a stream the far end cannot
// reassemble, and an RFC 4733 burst is identified by its shared start
// timestamp -- re-stamping turns one keypress into many or none.
TEST(RtpRawEgress, TheSerialisedDatagramIsByteExact)
{
	RtpReceiver rx;
	ASSERT_TRUE(rx.setRawPeer(peerAt("203.0.113.9", 4000)));

	const uint8_t body[] = {0x01, 0x8A, 0x00, 0xA0};   // an RFC 4733 event body
	const uint8_t kPt = 101, kMarker = 1;
	const uint16_t kSeq = 0x1234;
	const uint32_t kTs = 0xCAFEBABE, kSsrc = 0xDEADBEEF;

	ASSERT_TRUE(rx.sendRaw(packet(kPt, kSeq, kTs, body, sizeof(body), /*marker=*/true)));
	ASSERT_EQ(rx.sentRawCount(), 1u);

	const std::vector<uint8_t>& d = rx.lastRawDatagram();
	ASSERT_EQ(d.size(), 12u + sizeof(body));

	EXPECT_EQ(d[0], 0x80) << "V=2, P=0, X=0, CC=0";
	EXPECT_EQ(d[1], static_cast<uint8_t>((kMarker ? 0x80 : 0) | kPt)) << "marker + PT preserved";
	EXPECT_EQ((d[2] << 8) | d[3], kSeq) << "sequence preserved, not renumbered";
	EXPECT_EQ((static_cast<uint32_t>(d[4]) << 24) | (d[5] << 16) | (d[6] << 8) | d[7], kTs)
		<< "timestamp preserved -- an RFC 4733 burst is keyed on it";
	EXPECT_EQ((static_cast<uint32_t>(d[8]) << 24) | (d[9] << 16) | (d[10] << 8) | d[11], kSsrc)
		<< "SSRC forwarded: pure B2BUA transparency";
	EXPECT_EQ(std::memcmp(d.data() + 12, body, sizeof(body)), 0) << "payload untouched";
}

TEST(RtpRawEgress, AnOversizePayloadIsRefusedNotTruncated)
{
	RtpReceiver rx;
	ASSERT_TRUE(rx.setRawPeer(peerAt("203.0.113.9", 4000)));

	// Truncating would put a malformed packet on the wire; refusing drops one.
	std::vector<uint8_t> huge(RtpReceiver::MAX_DATAGRAM_BYTES, 0xAB);
	EXPECT_FALSE(rx.sendRaw(packet(0, 1, 160, huge.data(), huge.size())));
	EXPECT_EQ(rx.sentRawCount(), 0u);
}

// The relay as it will actually be wired: two receivers cross-connected, so a
// packet arriving on A leaves on B unchanged.
TEST(RtpRawEgress, CrossWiredReceiversRelayAPacketEndToEnd)
{
	RtpReceiver handsetLeg, trunkLeg;
	ASSERT_TRUE(trunkLeg.setRawPeer(peerAt("203.0.113.9", 4000)));
	ASSERT_TRUE(handsetLeg.setRawSink([&trunkLeg](const RtpReceiver::RtpPacket& p) {
		trunkLeg.sendRaw(p);
	}));

	const uint8_t ev[] = {0x05, 0x0A, 0x01, 0x40};
	ASSERT_TRUE(handsetLeg.dispatchRaw(packet(101, 77, 999, ev, sizeof(ev), /*marker=*/true)));

	ASSERT_EQ(trunkLeg.sentRawCount(), 1u) << "the packet crossed the relay";
	const std::vector<uint8_t>& d = trunkLeg.lastRawDatagram();
	ASSERT_EQ(d.size(), 12u + sizeof(ev));
	EXPECT_EQ(d[1] & 0x7F, 101) << "still telephone-event on the far side, not PCMU";
	EXPECT_EQ((d[2] << 8) | d[3], 77);
	EXPECT_EQ(std::memcmp(d.data() + 12, ev, sizeof(ev)), 0);
}

// A send-only relay leg has no Sink at all -- it exists to transmit. start()
// used to refuse that, the same guard that refused a raw-only receiver before
// #250 widened it.
TEST(RtpRawEgress, ASendOnlyLegCanStartWithNoSink)
{
	RtpReceiver rx;
	ASSERT_TRUE(rx.setRawPeer(peerAt("203.0.113.9", 4000)));
	EXPECT_TRUE(rx.start(0, nullptr)) << "a raw peer is a reason to be running";
	EXPECT_TRUE(rx.stop());
}

TEST(RtpRawEgress, StartStillRefusesWithNoSinkAndNoPeer)
{
	RtpReceiver rx;
	EXPECT_FALSE(rx.start(0, nullptr));
}

// The peer goes with the slot. A pooled receiver handed to a new call must not
// keep forwarding into the previous call's far end.
TEST(RtpRawEgress, StopClearsThePeer)
{
	RtpReceiver rx;
	ASSERT_TRUE(rx.setRawPeer(peerAt("203.0.113.9", 4000)));
	ASSERT_TRUE(rx.start(0, nullptr));
	ASSERT_TRUE(rx.stop());

	const uint8_t body[4] = {1, 2, 3, 4};
	EXPECT_FALSE(rx.sendRaw(packet(0, 1, 160, body, sizeof(body))))
		<< "a recycled receiver must not inherit the previous call's destination";
}

// A carrier re-INVITE can move media mid-call, so the peer must be replaceable
// on a receiver that is already running. Requested in review; without it the
// relay would keep forwarding to the OLD address after a re-INVITE and the call
// would go one-way with nothing in the signalling to explain it.
TEST(RtpRawEgress, ThePeerCanBeReplacedWhileTheStreamIsActive)
{
	RtpReceiver rx;
	ASSERT_TRUE(rx.setRawPeer(peerAt("203.0.113.9", 4000)));
	ASSERT_TRUE(rx.start(0, nullptr));

	const uint8_t body[4] = {1, 2, 3, 4};
	ASSERT_TRUE(rx.sendRaw(packet(0, 1, 160, body, sizeof(body))));
	ASSERT_EQ(rx.sentRawCount(), 1u);

	// Mid-call move, exactly as a re-INVITE would do it.
	ASSERT_TRUE(rx.setRawPeer(peerAt("198.51.100.7", 5000)))
		<< "must be callable while active";
	EXPECT_TRUE(rx.sendRaw(packet(0, 2, 320, body, sizeof(body))));
	EXPECT_EQ(rx.sentRawCount(), 2u);

	EXPECT_TRUE(rx.stop());
}

// "Returned false" and "dropped a packet" are different claims. The counter
// makes the second one assertable.
TEST(RtpRawEgress, AnOversizePacketIsCountedAsADropNotJustRefused)
{
	RtpReceiver rx;
	ASSERT_TRUE(rx.setRawPeer(peerAt("203.0.113.9", 4000)));
	ASSERT_EQ(rx.droppedRawCount(), 0u);

	std::vector<uint8_t> huge(RtpReceiver::MAX_DATAGRAM_BYTES, 0xAB);
	EXPECT_FALSE(rx.sendRaw(packet(0, 1, 160, huge.data(), huge.size())));

	EXPECT_EQ(rx.droppedRawCount(), 1u) << "the drop is recorded, not merely refused";
	EXPECT_EQ(rx.sentRawCount(), 0u);
}

// An unconfigured leg is NOT a drop. Nothing was lost -- there was never a
// destination -- and conflating the two would make the drop counter useless as
// a diagnostic for a relay that is losing media.
TEST(RtpRawEgress, NoPeerIsNotCountedAsADrop)
{
	RtpReceiver rx;
	const uint8_t body[4] = {1, 2, 3, 4};
	EXPECT_FALSE(rx.sendRaw(packet(0, 1, 160, body, sizeof(body))));
	EXPECT_EQ(rx.droppedRawCount(), 0u);
	EXPECT_EQ(rx.sentRawCount(), 0u);
}
