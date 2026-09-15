// SdpParse_test.cpp — issue #196: what the re2c-generated parser actually does
// with a body.
//
// SdpModel_test.cpp pins the structural invariants (offsets only, memcpy-safe,
// size ceiling). This file pins behaviour, and it is weighted toward the three
// cases the issue was filed for rather than toward coverage:
//
//   1. MULTI-SECTION. RFC 3264 §8 requires an answer to carry the same NUMBER
//      of m= sections as the offer, so sections have to survive parsing even
//      when they are rejected. The old six-span cache could represent exactly
//      one m= line and silently dropped the rest.
//
//   2. MEDIA-LEVEL c= WITH NO SESSION-LEVEL c=. This is #196 item 2 and it is a
//      real interop failure, not a tidiness complaint: some phones emit c= only
//      per media, the old accessor looked at the session level alone, and the
//      anchoring path was left with no address to aim RTP at.
//
//   3. FAIL CLOSED ON OVERFLOW. The CWE-674 case. A body of repeated a= lines
//      must be REFUSED at the cap, not truncated-and-accepted, and the refusal
//      must cost the same stack as a one-attribute body because nothing about
//      the parse is a function of attacker-chosen structure.

#include <gtest/gtest.h>

#include <string>

#include "Sdp.hpp"

namespace
{
	// A realistic single-audio offer, session-level c=, as a hardphone emits it.
	const char* kSimpleOffer =
		"v=0\r\n"
		"o=- 12345 1 IN IP4 192.168.1.50\r\n"
		"s=-\r\n"
		"c=IN IP4 192.168.1.50\r\n"
		"t=0 0\r\n"
		"m=audio 4000 RTP/AVP 0 8 101\r\n"
		"a=rtpmap:0 PCMU/8000\r\n"
		"a=rtpmap:8 PCMA/8000\r\n"
		"a=rtpmap:101 telephone-event/8000\r\n"
		"a=fmtp:101 0-15\r\n"
		"a=ptime:20\r\n"
		"a=sendrecv\r\n";

	std::string repeatedAttrs(unsigned n)
	{
		// The UNISOC T612 shape: the same attribute over and over. The decoder
		// there recursed once per token; this parser must not care how many there
		// are beyond refusing past the cap.
		std::string s =
			"v=0\r\n"
			"o=- 1 1 IN IP4 10.0.0.1\r\n"
			"s=-\r\n"
			"c=IN IP4 10.0.0.1\r\n"
			"t=0 0\r\n"
			"m=audio 4000 RTP/AVP 0\r\n";
		for (unsigned i = 0; i < n; ++i) s += "a=acap:1\r\n";
		return s;
	}
}

// ── Baseline ─────────────────────────────────────────────────────────────────

TEST(SdpParse, SimpleOfferPopulatesSessionAndOneSection)
{
	sdp::Session s{};
	const std::string_view body{kSimpleOffer};
	ASSERT_EQ(sdp::parse(body, s), sdp::Verdict::Ok);

	// Whole lines, prefix included -- the span convention in Sdp.hpp. This is
	// what keeps the legacy SipSdpMessage accessors byte-identical for their
	// existing callers.
	EXPECT_EQ(sdp::view(body, s.version), "v=0");
	EXPECT_EQ(sdp::view(body, s.name), "s=-");
	EXPECT_EQ(sdp::view(body, s.time), "t=0 0");
	EXPECT_EQ(sdp::view(body, s.origin), "o=- 12345 1 IN IP4 192.168.1.50");

	ASSERT_EQ(s.nMedia, 1);
	const sdp::Media& m = s.media[0];
	EXPECT_EQ(sdp::view(body, m.typeName), "audio");
	EXPECT_EQ(sdp::view(body, m.proto), "RTP/AVP");
	EXPECT_EQ(m.port, 4000);
	ASSERT_EQ(m.nFmt, 3);
	EXPECT_EQ(m.fmt[0], 0);
	EXPECT_EQ(m.fmt[1], 8);
	EXPECT_EQ(m.fmt[2], 101);
	EXPECT_FALSE(m.malformedFmt);

	// The whole m= line is kept verbatim so a section can be relayed untouched.
	EXPECT_EQ(sdp::view(body, m.line), "m=audio 4000 RTP/AVP 0 8 101");
}

TEST(SdpParse, AttributeKindsAndPayloadTypesAreResolvedAtParseTime)
{
	sdp::Session s{};
	const std::string_view body{kSimpleOffer};
	ASSERT_EQ(sdp::parse(body, s), sdp::Verdict::Ok);
	ASSERT_EQ(s.nMedia, 1);
	const sdp::Media& m = s.media[0];
	ASSERT_EQ(m.nAttrs, 6);

	EXPECT_EQ(m.attrs[0].kind, sdp::AttrKind::Rtpmap);
	EXPECT_EQ(m.attrs[0].pt, 0);
	EXPECT_EQ(sdp::view(body, m.attrs[0].value), "0 PCMU/8000");

	EXPECT_EQ(m.attrs[2].kind, sdp::AttrKind::Rtpmap);
	EXPECT_EQ(m.attrs[2].pt, 101);

	EXPECT_EQ(m.attrs[3].kind, sdp::AttrKind::Fmtp);
	EXPECT_EQ(m.attrs[3].pt, 101);

	EXPECT_EQ(m.attrs[4].kind, sdp::AttrKind::Ptime);
	EXPECT_EQ(m.attrs[4].pt, 0xFF) << "ptime carries no payload type";

	// Property form: no ':' at all, so a value is absent rather than empty-string.
	EXPECT_EQ(m.attrs[5].kind, sdp::AttrKind::Sendrecv);
	EXPECT_TRUE(m.attrs[5].value.absent());
	EXPECT_EQ(sdp::view(body, m.attrs[5].name), "sendrecv");
}

// A prefix match would let a nonsense attribute change a stream's direction.
TEST(SdpParse, KeywordMatchingRequiresTheWholeName)
{
	const std::string body =
		"v=0\r\nm=audio 4000 RTP/AVP 0\r\n"
		"a=sendrecvX\r\n"
		"a=rtpmapp:0 PCMU/8000\r\n";
	sdp::Session s{};
	ASSERT_EQ(sdp::parse(body, s), sdp::Verdict::Ok);
	ASSERT_EQ(s.nMedia, 1);
	ASSERT_EQ(s.media[0].nAttrs, 2);
	EXPECT_EQ(s.media[0].attrs[0].kind, sdp::AttrKind::Other);
	EXPECT_EQ(s.media[0].attrs[1].kind, sdp::AttrKind::Other);
}

// ── 1. Multi-section ─────────────────────────────────────────────────────────

TEST(SdpParse, EveryMediaSectionSurvives)
{
	const std::string body =
		"v=0\r\n"
		"o=- 1 1 IN IP4 10.0.0.1\r\n"
		"s=-\r\n"
		"c=IN IP4 10.0.0.1\r\n"
		"t=0 0\r\n"
		"m=audio 4000 RTP/AVP 0\r\n"
		"a=sendrecv\r\n"
		"m=video 4002 RTP/AVP 96\r\n"
		"a=recvonly\r\n"
		"m=application 4004 UDP/BFCP *\r\n";

	sdp::Session s{};
	ASSERT_EQ(sdp::parse(body, s), sdp::Verdict::Ok);
	ASSERT_EQ(s.nMedia, 3) << "RFC 3264 s8: an answer must match the offer's section count";

	EXPECT_EQ(sdp::view(body, s.media[0].typeName), "audio");
	EXPECT_EQ(sdp::view(body, s.media[1].typeName), "video");
	EXPECT_EQ(sdp::view(body, s.media[2].typeName), "application");

	// Attributes land in the section they follow, not in a global bucket.
	EXPECT_EQ(s.media[0].nAttrs, 1);
	EXPECT_EQ(s.media[1].nAttrs, 1);
	EXPECT_EQ(s.media[2].nAttrs, 0);
	EXPECT_EQ(sdp::effectiveDirection(s, 0), sdp::Direction::Sendrecv);
	EXPECT_EQ(sdp::effectiveDirection(s, 1), sdp::Direction::Recvonly);

	// A non-numeric <fmt> is flagged, and the section is still preserved.
	EXPECT_TRUE(s.media[2].malformedFmt);
	EXPECT_EQ(sdp::view(body, s.media[2].line), "m=application 4004 UDP/BFCP *");
}

TEST(SdpParse, ARejectedSectionIsKeptWithPortZero)
{
	// RFC 3264 §6: port 0 rejects a stream. The section must still be present, or
	// the answer's section count stops matching the offer's.
	const std::string body =
		"v=0\r\nm=audio 4000 RTP/AVP 0\r\nm=video 0 RTP/AVP 96\r\n";
	sdp::Session s{};
	ASSERT_EQ(sdp::parse(body, s), sdp::Verdict::Ok);
	ASSERT_EQ(s.nMedia, 2);
	EXPECT_EQ(s.media[1].port, 0);
	EXPECT_EQ(sdp::view(body, s.media[1].typeName), "video");
}

// ── 2. Media-level c= — the interop bug #196 was filed for ───────────────────

TEST(SdpParse, MediaLevelConnectionIsFoundWhenTheSessionHasNone)
{
	// The failing shape: no session-level c= at all. A reader that consulted only
	// the session level got nothing and had no address to send RTP to.
	const std::string body =
		"v=0\r\n"
		"o=- 1 1 IN IP4 10.0.0.1\r\n"
		"s=-\r\n"
		"t=0 0\r\n"
		"m=audio 4000 RTP/AVP 0\r\n"
		"c=IN IP4 198.51.100.7\r\n";

	sdp::Session s{};
	ASSERT_EQ(sdp::parse(body, s), sdp::Verdict::Ok);
	EXPECT_TRUE(s.connection.absent()) << "there genuinely is no session-level c=";
	EXPECT_EQ(sdp::view(body, sdp::effectiveConnection(s, 0)), "c=IN IP4 198.51.100.7");
}

TEST(SdpParse, MediaLevelConnectionOverridesTheSessionLevelPerSection)
{
	const std::string body =
		"v=0\r\n"
		"c=IN IP4 10.0.0.1\r\n"
		"m=audio 4000 RTP/AVP 0\r\n"
		"c=IN IP4 198.51.100.7\r\n"
		"m=video 4002 RTP/AVP 96\r\n";

	sdp::Session s{};
	ASSERT_EQ(sdp::parse(body, s), sdp::Verdict::Ok);
	ASSERT_EQ(s.nMedia, 2);

	// Section 0 overrides; section 1 inherits. Both in one body, because getting
	// only one of the two right is the easy half.
	EXPECT_EQ(sdp::view(body, sdp::effectiveConnection(s, 0)), "c=IN IP4 198.51.100.7");
	EXPECT_EQ(sdp::view(body, sdp::effectiveConnection(s, 1)), "c=IN IP4 10.0.0.1");
}

// ── 3. Fail closed ───────────────────────────────────────────────────────────

TEST(SdpParse, AtTheAttributeCapTheBodyIsStillAccepted)
{
	// The boundary itself must be usable, or the cap is effectively one lower
	// than it reads.
	const std::string body = repeatedAttrs(sdp::Limits::kMaxAttributesPerSection);
	sdp::Session s{};
	ASSERT_EQ(sdp::parse(body, s), sdp::Verdict::Ok);
	ASSERT_EQ(s.nMedia, 1);
	EXPECT_EQ(s.media[0].nAttrs, sdp::Limits::kMaxAttributesPerSection);

	// acap is stored as bytes and never interpreted — that is the whole point.
	EXPECT_EQ(s.media[0].attrs[0].kind, sdp::AttrKind::Other);
}

TEST(SdpParse, PastTheAttributeCapTheBodyIsRefusedNotTruncated)
{
	// Refused, NOT accepted-with-the-extras-dropped. A truncating parse would
	// hand a handler a body that reads as complete while silently missing
	// attributes it might have acted on.
	const std::string body = repeatedAttrs(sdp::Limits::kMaxAttributesPerSection + 1);
	sdp::Session s{};
	EXPECT_EQ(sdp::parse(body, s), sdp::Verdict::TooManyAttributes);
}

// The CWE-674 shape at scale. 500 repeated attributes is ~63x the cap; the
// parser must refuse, promptly, without the work or the stack being a function
// of the count.
TEST(SdpParse, AMassiveRepeatedAttributeBodyIsRefusedPromptly)
{
	const std::string body = repeatedAttrs(500);
	sdp::Session s{};
	EXPECT_EQ(sdp::parse(body, s), sdp::Verdict::TooManyAttributes);
}

TEST(SdpParse, PastTheMediaSectionCapTheBodyIsRefused)
{
	std::string body = "v=0\r\n";
	for (unsigned i = 0; i <= sdp::Limits::kMaxMediaSections; ++i)
	{
		body += "m=audio " + std::to_string(4000 + i * 2) + " RTP/AVP 0\r\n";
	}
	sdp::Session s{};
	EXPECT_EQ(sdp::parse(body, s), sdp::Verdict::TooManyMediaSections);
}

TEST(SdpParse, TooManyLinesIsRefused)
{
	std::string body = "v=0\r\n";
	for (unsigned i = 0; i < SdpLimits::kMaxLines + 10; ++i) body += "i=filler\r\n";
	sdp::Session s{};
	EXPECT_EQ(sdp::parse(body, s), sdp::Verdict::TooManyLines);
}

// ── Reset semantics ──────────────────────────────────────────────────────────

TEST(SdpParse, ReparseFullyReplacesThePreviousBody)
{
	// The recycled pool-slot case. A field present in the PREVIOUS body must not
	// survive into this one, which is what makes a stale model dangerous rather
	// than merely out of date.
	sdp::Session s{};
	const std::string_view first{kSimpleOffer};
	ASSERT_EQ(sdp::parse(first, s), sdp::Verdict::Ok);
	ASSERT_EQ(s.nMedia, 1);
	ASSERT_FALSE(s.connection.absent());

	const std::string second = "v=0\r\nt=0 0\r\n";   // no c=, no m=
	ASSERT_EQ(sdp::parse(second, s), sdp::Verdict::Ok);
	EXPECT_EQ(s.nMedia, 0) << "the previous body's media section must be gone";
	EXPECT_TRUE(s.connection.absent()) << "the previous body's c= must be gone";
	EXPECT_EQ(s.media[0].nAttrs, 0);
}

// ── Hold detection, both signals ─────────────────────────────────────────────

TEST(SdpParse, HoldIsDetectedFromDirectionAndFromTheLegacyZeroAddress)
{
	const std::string modern =
		"v=0\r\nc=IN IP4 10.0.0.1\r\nm=audio 4000 RTP/AVP 0\r\na=sendonly\r\n";
	sdp::Session a{};
	ASSERT_EQ(sdp::parse(modern, a), sdp::Verdict::Ok);
	EXPECT_TRUE(sdp::isHold(a, modern, 0));

	// RFC 2543 form: direction says nothing, the address is the blackhole.
	const std::string legacy =
		"v=0\r\nc=IN IP4 0.0.0.0\r\nm=audio 4000 RTP/AVP 0\r\n";
	sdp::Session b{};
	ASSERT_EQ(sdp::parse(legacy, b), sdp::Verdict::Ok);
	EXPECT_TRUE(sdp::isHold(b, legacy, 0))
		<< "older phones hold by blackholing the address, not by changing direction";

	const std::string active =
		"v=0\r\nc=IN IP4 10.0.0.1\r\nm=audio 4000 RTP/AVP 0\r\na=sendrecv\r\n";
	sdp::Session c{};
	ASSERT_EQ(sdp::parse(active, c), sdp::Verdict::Ok);
	EXPECT_FALSE(sdp::isHold(c, active, 0));
}

// ── Line-ending tolerance ────────────────────────────────────────────────────

TEST(SdpParse, BareNewlinesAreToleratedLikeTheOldParser)
{
	// Behaviour deliberately preserved from the parser this replaces: primary
	// "\r\n", bare "\n" accepted. Changing it would reject bodies the PBX
	// previously handled.
	const std::string body =
		"v=0\nc=IN IP4 10.0.0.1\nm=audio 4000 RTP/AVP 0\na=sendonly\n";
	sdp::Session s{};
	ASSERT_EQ(sdp::parse(body, s), sdp::Verdict::Ok);
	ASSERT_EQ(s.nMedia, 1);
	EXPECT_EQ(sdp::view(body, s.media[0].typeName), "audio");
	EXPECT_EQ(sdp::effectiveDirection(s, 0), sdp::Direction::Sendonly);
}

TEST(SdpParse, AnEmptyBodyParsesToAnEmptyModel)
{
	sdp::Session s{};
	EXPECT_EQ(sdp::parse(std::string_view{}, s), sdp::Verdict::Ok);
	EXPECT_EQ(s.nMedia, 0);
	EXPECT_EQ(s.lines, 0);
}
