// Issue #101(B): SipSdpMessage caches one single-pass parse of the SDP body
// instead of re-parsing it on every accessor call. The cache is keyed on
// SipMessage's body generation counter, so these tests are really about one
// question: does every path that changes the body make the cache notice?
//
// The dangerous path is the pool one. RequestsHandler pre-allocates
// POCKETDIAL_MSG_POOL SipSdpMessages and hands the same objects out over and
// over via reset() and `*msg = source`. A cache that survives either of those
// serves the PREVIOUS call's SDP to the current call — a wrong c= line or m=
// port means media set up against the wrong endpoint, which is far worse than
// the re-parse cost this change removes.

#include <gtest/gtest.h>

#include "SipSdpMessage.hpp"

#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

namespace
{
	sockaddr_in localAddr()
	{
		sockaddr_in s{};
		s.sin_family      = AF_INET;
		s.sin_addr.s_addr = inet_addr("127.0.0.1");
		s.sin_port        = htons(5060);
		return s;
	}

	// A complete INVITE with an SDP offer, Content-Length kept honest so the
	// message parses the same way one off the wire would.
	std::string inviteWith(const std::string& body)
	{
		return "INVITE sip:200@server SIP/2.0\r\n"
		       "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK1\r\n"
		       "From: <sip:100@server>;tag=a\r\n"
		       "To: <sip:200@server>\r\n"
		       "Call-ID: call-one\r\n"
		       "CSeq: 1 INVITE\r\n"
		       "Content-Type: application/sdp\r\n"
		       "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
	}

	const char* kBodyA =
		"v=0\r\n"
		"o=- 111 111 IN IP4 192.168.1.10\r\n"
		"s=call-a\r\n"
		"c=IN IP4 192.168.1.10\r\n"
		"t=0 0\r\n"
		"m=audio 4000 RTP/AVP 0 8 101\r\n"
		"a=rtpmap:0 PCMU/8000\r\n";

	// Deliberately a DIFFERENT SHAPE from kBodyA, not just different values: every
	// line has a different length, so the two bodies' field offsets do not line
	// up. That matters because the cache stores offsets — if body B's lines sat at
	// body A's offsets, a cache that was never invalidated would read B at A's
	// offsets and still return B's correct text, and every invalidation test here
	// would pass while testing nothing. (Confirmed by mutation: with same-shape
	// bodies, ResetInvalidatesCache passes against a cache that never
	// invalidates. With these, it fails.)
	const char* kBodyB =
		"v=0\r\n"
		"o=- 22 22 IN IP4 10.1.1.7\r\n"
		"s=b\r\n"
		"c=IN IP4 10.1.1.7\r\n"
		"t=1 2\r\n"
		"m=audio 5678 RTP/AVP 8\r\n";
}

// Baseline: the cached parse must return exactly what the old per-call parse
// did, including on repeat reads.
TEST(SipSdpMessageCache, AccessorsReturnParsedFieldsAndAreStableAcrossCalls) {
	SipSdpMessage m(inviteWith(kBodyA), localAddr());

	EXPECT_EQ(std::string(m.getVersion()), "v=0");
	EXPECT_EQ(std::string(m.getOriginator()), "o=- 111 111 IN IP4 192.168.1.10");
	EXPECT_EQ(std::string(m.getSessionName()), "s=call-a");
	EXPECT_EQ(std::string(m.getConnectionInformation()), "c=IN IP4 192.168.1.10");
	EXPECT_EQ(std::string(m.getTime()), "t=0 0");
	EXPECT_EQ(std::string(m.getMedia()), "m=audio 4000 RTP/AVP 0 8 101");
	EXPECT_EQ(m.getRtpPort(), 4000);

	// Second pass reads from the cache — same answers, not empty views.
	EXPECT_EQ(std::string(m.getVersion()), "v=0");
	EXPECT_EQ(std::string(m.getConnectionInformation()), "c=IN IP4 192.168.1.10");
	EXPECT_EQ(m.getRtpPort(), 4000);
}

// A body with no SDP at all: every field absent, and asking twice must not
// somehow populate it.
TEST(SipSdpMessageCache, AbsentFieldsReturnEmptyViews) {
	SipSdpMessage m(inviteWith(""), localAddr());

	EXPECT_TRUE(m.getVersion().empty());
	EXPECT_TRUE(m.getMedia().empty());
	EXPECT_TRUE(m.getConnectionInformation().empty());
	EXPECT_EQ(m.getRtpPort(), 0);
	EXPECT_TRUE(m.getMedia().empty());
}

// setBody() is the park path's tool (ParkOrbit.cpp swaps each leg's SDP onto
// the opposite dialog). Reading before the swap must not pin the old answer.
TEST(SipSdpMessageCache, SetBodyInvalidatesCache) {
	SipSdpMessage m(inviteWith(kBodyA), localAddr());
	ASSERT_EQ(m.getRtpPort(), 4000);                        // prime the cache
	ASSERT_EQ(std::string(m.getSessionName()), "s=call-a");

	m.setBody(kBodyB);

	EXPECT_EQ(std::string(m.getSessionName()), "s=b");
	EXPECT_EQ(std::string(m.getConnectionInformation()), "c=IN IP4 10.1.1.7");
	EXPECT_EQ(std::string(m.getMedia()), "m=audio 5678 RTP/AVP 8");
	EXPECT_EQ(m.getRtpPort(), 5678);
}

// setMedia() rewrites only the m= line, in place, via setBody().
TEST(SipSdpMessageCache, SetMediaInvalidatesCache) {
	SipSdpMessage m(inviteWith(kBodyA), localAddr());
	ASSERT_EQ(m.getRtpPort(), 4000);

	m.setMedia("m=audio 9999 RTP/AVP 8");

	EXPECT_EQ(std::string(m.getMedia()), "m=audio 9999 RTP/AVP 8");
	EXPECT_EQ(m.getRtpPort(), 9999);
	// Neighbouring fields still resolve — the spans after the edited line moved,
	// so this also catches offsets that were not recomputed.
	EXPECT_EQ(std::string(m.getConnectionInformation()), "c=IN IP4 192.168.1.10");
}

// enforceG711() rewrites the codec list on the m= line — a body mutation that
// does NOT go through setBody().
TEST(SipSdpMessageCache, EnforceG711InvalidatesCache) {
	SipSdpMessage m(inviteWith(kBodyA), localAddr());
	ASSERT_EQ(std::string(m.getMedia()), "m=audio 4000 RTP/AVP 0 8 101");

	m.enforceG711();

	EXPECT_EQ(std::string(m.getMedia()), "m=audio 4000 RTP/AVP 0 8 101");
	EXPECT_EQ(m.getRtpPort(), 4000);

	// And again on a body whose codec list actually changes length, so the
	// trailing spans shift.
	SipSdpMessage wide(inviteWith(
		"v=0\r\n"
		"o=- 1 1 IN IP4 10.0.0.5\r\n"
		"s=wide\r\n"
		"c=IN IP4 10.0.0.5\r\n"
		"t=0 0\r\n"
		"m=audio 4002 RTP/AVP 0 8 9 18 101\r\n"
		"a=rtpmap:0 PCMU/8000\r\n"), localAddr());
	ASSERT_EQ(std::string(wide.getMedia()), "m=audio 4002 RTP/AVP 0 8 9 18 101");

	wide.enforceG711();

	EXPECT_EQ(std::string(wide.getMedia()), "m=audio 4002 RTP/AVP 0 8 101");
	EXPECT_EQ(wide.getRtpPort(), 4002);
}

// Note on this one: with the body emptied, viewOf()'s out-of-range guard would
// also report every field absent even if the generation counter had missed the
// mutation, so this asserts the observable contract rather than isolating the
// invalidation. The clearBody() bump is kept anyway — leaning on the guard for
// correctness is precisely the fragility this change exists to remove.
TEST(SipSdpMessageCache, ClearBodyInvalidatesCache) {
	SipSdpMessage m(inviteWith(kBodyA), localAddr());
	ASSERT_EQ(m.getRtpPort(), 4000);

	m.clearBody();

	EXPECT_TRUE(m.getMedia().empty());
	EXPECT_TRUE(m.getVersion().empty());
	EXPECT_EQ(m.getRtpPort(), 0);

	// Repopulating must work too — a cache left marked-valid over the empty body
	// would report the new SDP as absent.
	m.setBody(kBodyB);
	EXPECT_EQ(std::string(m.getSessionName()), "s=b");
	EXPECT_EQ(m.getRtpPort(), 5678);
}

// THE pool landmine. getMessageFromPool() recycles a slot with reset(); if the
// cache survived that, a new call would read the previous call's c= / m= lines.
TEST(SipSdpMessageCache, ResetInvalidatesCache) {
	SipSdpMessage m(inviteWith(kBodyA), localAddr());
	ASSERT_EQ(std::string(m.getConnectionInformation()), "c=IN IP4 192.168.1.10");
	ASSERT_EQ(m.getRtpPort(), 4000);

	m.reset(inviteWith(kBodyB), localAddr());   // slot handed back out

	EXPECT_EQ(std::string(m.getVersion()), "v=0");
	EXPECT_EQ(std::string(m.getOriginator()), "o=- 22 22 IN IP4 10.1.1.7");
	EXPECT_EQ(std::string(m.getSessionName()), "s=b");
	EXPECT_EQ(std::string(m.getConnectionInformation()), "c=IN IP4 10.1.1.7");
	EXPECT_EQ(std::string(m.getTime()), "t=1 2");
	EXPECT_EQ(std::string(m.getMedia()), "m=audio 5678 RTP/AVP 8");
	EXPECT_EQ(m.getRtpPort(), 5678);
}

// A field present in the old body and absent from the new one must not survive
// in the cache — the parse rebuilds from scratch rather than updating in place.
//
// The replacement body is padded to be LONGER than kBodyA on purpose. A short
// one would put every stale span out of range, where viewOf()'s guard reports
// them absent and the test would pass against a cache that never invalidated.
// Padded, the stale spans stay in range and resolve to filler text, so only real
// invalidation produces the empty views asserted below.
TEST(SipSdpMessageCache, FieldDroppedByNewBodyDoesNotSurvive) {
	SipSdpMessage m(inviteWith(kBodyA), localAddr());
	ASSERT_EQ(std::string(m.getSessionName()), "s=call-a");
	ASSERT_FALSE(m.getMedia().empty());

	m.reset(inviteWith(
		"v=0\r\n"
		"a=filler-aaaaaaaaaaaaaaaaaaaaaaaaaa\r\n"
		"a=filler-bbbbbbbbbbbbbbbbbbbbbbbbbb\r\n"
		"t=0 0\r\n"
		"a=filler-cccccccccccccccccccccccccc\r\n"), localAddr());

	EXPECT_EQ(std::string(m.getVersion()), "v=0");
	EXPECT_TRUE(m.getSessionName().empty());
	EXPECT_TRUE(m.getMedia().empty());
	EXPECT_TRUE(m.getConnectionInformation().empty());
	EXPECT_EQ(m.getRtpPort(), 0);
}

// The other recycle path: getMessageFromPool(const SipMessage&) does
// `*msg = source`. The cache is stored as offsets, not string_views, precisely
// so this defaulted copy stays correct — the destination must read its OWN body
// and must not be left pointing into the source's, which is about to be reused.
TEST(SipSdpMessageCache, CopyAssignedSlotReadsItsOwnBody) {
	SipSdpMessage source(inviteWith(kBodyA), localAddr());
	SipSdpMessage slot(inviteWith(kBodyB), localAddr());

	ASSERT_EQ(source.getRtpPort(), 4000);
	ASSERT_EQ(slot.getRtpPort(), 5678);   // both caches primed, and they disagree

	slot = source;

	EXPECT_EQ(std::string(slot.getSessionName()), "s=call-a");
	EXPECT_EQ(std::string(slot.getConnectionInformation()), "c=IN IP4 192.168.1.10");
	EXPECT_EQ(slot.getRtpPort(), 4000);

	// Now recycle the source out from under the copy. If the copy's cache were
	// string_views into source's body, this is where it would dangle.
	source.reset(inviteWith(kBodyB), localAddr());
	ASSERT_EQ(source.getRtpPort(), 5678);

	EXPECT_EQ(std::string(slot.getSessionName()), "s=call-a");
	EXPECT_EQ(std::string(slot.getConnectionInformation()), "c=IN IP4 192.168.1.10");
	EXPECT_EQ(slot.getRtpPort(), 4000);
}

// The path the pool ACTUALLY takes, and the one the two-SipSdpMessage-lvalues
// test above does NOT exercise. RequestsHandler holds shared_ptr<SipMessage>, so
// getMessageFromPool(const SipMessage&)'s `*msg = source` binds both sides as
// SipMessage — a base-subobject assignment. Only SipMessage's members are
// assigned; the derived cache is left exactly as the slot's PREVIOUS call left
// it. If the base assignment does not invalidate, the slot answers the new call
// with the old call's c=/m= lines: media negotiated against the wrong endpoint.
TEST(SipSdpMessageCache, PoolStyleBaseSubobjectAssignmentInvalidatesCache) {
	SipSdpMessage source(inviteWith(kBodyA), localAddr());
	SipSdpMessage slot(inviteWith(kBodyB), localAddr());

	ASSERT_EQ(source.getRtpPort(), 4000);
	ASSERT_EQ(slot.getRtpPort(), 5678);   // slot's cache primed with the old call

	SipMessage&       slotBase   = slot;
	const SipMessage& sourceBase = source;
	slotBase = sourceBase;                // literally what the pool does

	EXPECT_EQ(std::string(slot.getSessionName()), "s=call-a");
	EXPECT_EQ(std::string(slot.getConnectionInformation()), "c=IN IP4 192.168.1.10");
	EXPECT_EQ(std::string(slot.getMedia()), "m=audio 4000 RTP/AVP 0 8 101");
	EXPECT_EQ(slot.getRtpPort(), 4000);
}

// The subtler sibling of the test above: assignment between two SipSdpMessages,
// where the SOURCE's own cache is stale. The implicit operator= would bump this
// object's body generation (through SipMessage::operator=) and then overwrite
// its cache generation with the source's — two private counters crossed. Where
// they collide, the destination reads the source's OLD spans against the body it
// just received.
//
// That collision is arithmetic, so this sweeps a range of prior-mutation counts
// on both objects rather than hand-picking the pair that happens to line up
// today; a test tuned to today's exact counter values would stop covering this
// the moment a mutation path is added or removed.
TEST(SipSdpMessageCache, AssignmentFromStaleSourceDoesNotAdoptItsCache) {
	for (int destMutations = 0; destMutations < 6; ++destMutations)
	{
		for (int sourceMutations = 0; sourceMutations < 6; ++sourceMutations)
		{
			SipSdpMessage source(inviteWith(kBodyA), localAddr());
			for (int i = 0; i < sourceMutations; ++i) source.setBody(kBodyA);
			ASSERT_EQ(source.getRtpPort(), 4000);   // prime it...
			source.setBody(kBodyB);                 // ...then strand it

			SipSdpMessage dest(inviteWith(kBodyA), localAddr());
			for (int i = 0; i < destMutations; ++i) dest.setBody(kBodyA);

			dest = source;

			const std::string where = "dest=" + std::to_string(destMutations) +
			                          " source=" + std::to_string(sourceMutations);
			EXPECT_EQ(std::string(dest.getSessionName()), "s=b") << where;
			EXPECT_EQ(std::string(dest.getConnectionInformation()), "c=IN IP4 10.1.1.7") << where;
			EXPECT_EQ(dest.getRtpPort(), 5678) << where;
		}
	}
}

// Same for the copy constructor.
TEST(SipSdpMessageCache, CopyConstructedMessageReadsItsOwnBody) {
	SipSdpMessage source(inviteWith(kBodyA), localAddr());
	ASSERT_EQ(source.getRtpPort(), 4000);

	SipSdpMessage copy(source);
	source.reset(inviteWith(kBodyB), localAddr());

	EXPECT_EQ(std::string(copy.getSessionName()), "s=call-a");
	EXPECT_EQ(copy.getRtpPort(), 4000);
	EXPECT_EQ(source.getRtpPort(), 5678);
}

// Line-ending handling is unchanged from the old per-accessor parse: "\r\n"
// primary, bare "\n" fallback, and last-one-wins on a repeated field.
TEST(SipSdpMessageCache, LineEndingAndDuplicateFieldBehaviorUnchanged) {
	SipSdpMessage lf(inviteWith(
		"v=0\n"
		"o=- 3 3 IN IP4 10.0.0.7\n"
		"c=IN IP4 10.0.0.7\n"
		"m=audio 1234 RTP/AVP 0\n"), localAddr());
	EXPECT_EQ(std::string(lf.getConnectionInformation()), "c=IN IP4 10.0.0.7");
	EXPECT_EQ(lf.getRtpPort(), 1234);

	// Issue #196: two m=audio lines are two STREAMS (RFC 8866 §5.14), not a
	// field repeated with last-one-wins. The accessors report the first audio
	// section, which is the one this PBX terminates or relays.
	SipSdpMessage dup(inviteWith(
		"v=0\r\n"
		"m=audio 1111 RTP/AVP 0\r\n"
		"m=audio 2222 RTP/AVP 0\r\n"), localAddr());
	EXPECT_EQ(std::string(dup.getMedia()), "m=audio 1111 RTP/AVP 0");
	EXPECT_EQ(dup.getRtpPort(), 1111);

	// And a video-first offer no longer reads the video line as "the" media:
	SipSdpMessage vfirst(inviteWith(
		"v=0\r\n"
		"c=IN IP4 10.0.0.7\r\n"
		"m=video 5000 RTP/AVP 96\r\n"
		"m=audio 3333 RTP/AVP 0\r\n"
		"c=IN IP4 10.0.0.8\r\n"), localAddr());
	EXPECT_EQ(std::string(vfirst.getMedia()), "m=audio 3333 RTP/AVP 0");
	EXPECT_EQ(vfirst.getRtpPort(), 3333);
	EXPECT_EQ(std::string(vfirst.getConnectionInformation()), "c=IN IP4 10.0.0.8")
		<< "the media-level c= applies to the audio stream (RFC 8866 §5.7)";
}
