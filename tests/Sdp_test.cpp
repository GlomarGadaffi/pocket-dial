// Issue #196: the RFC 8866 SDP model. Pins the things the six-field scanner got
// wrong -- one m= assumed, no media-level c=, no attribute scoping -- and the
// three invariants the model must keep: flat bounded parse, offsets not views,
// fixed capacity with counted overflow.

#include <gtest/gtest.h>

#include <string>
#include <string_view>

#include "Sdp.hpp"
#include "SipMessage.hpp"

namespace
{
	std::string_view v(std::string_view body, sdp::Span s) { return sdp::view(body, s); }

	const std::string kAudioVideo =
		"v=0\r\n"
		"o=alice 2890844526 2890844526 IN IP4 192.168.1.10\r\n"
		"s=-\r\n"
		"c=IN IP4 192.168.1.10\r\n"
		"t=0 0\r\n"
		"a=sendrecv\r\n"
		"m=video 51372 RTP/AVP 96\r\n"
		"a=rtpmap:96 H264/90000\r\n"
		"m=audio 49170 RTP/AVP 8 0 101\r\n"
		"c=IN IP4 192.168.1.77\r\n"
		"a=rtpmap:8 PCMA/8000\r\n"
		"a=rtpmap:0 PCMU/8000\r\n"
		"a=rtpmap:101 telephone-event/8000\r\n"
		"a=fmtp:101 0-16\r\n"
		"a=ptime:20\r\n"
		"a=sendonly\r\n";
}

TEST(SdpModel, ParsesEveryMediaSectionNotJustTheFirst)
{
	sdp::Session s;
	sdp::parse(kAudioVideo, s);

	ASSERT_EQ(s.mediaCount, 2u);
	EXPECT_EQ(s.media[0].type, sdp::MediaType::Video);
	EXPECT_EQ(s.media[0].port, 51372u);
	EXPECT_EQ(s.media[1].type, sdp::MediaType::Audio);
	EXPECT_EQ(s.media[1].port, 49170u);
	EXPECT_EQ(s.firstAudio(), 1) << "the audio section is the SECOND m=; the old scanner would have read video";

	const sdp::Media& a = s.media[1];
	ASSERT_EQ(a.fmtCount, 3u);
	EXPECT_EQ(a.fmt[0], 8); EXPECT_EQ(a.fmt[1], 0); EXPECT_EQ(a.fmt[2], 101);
	EXPECT_EQ(v(kAudioVideo, a.proto), "RTP/AVP");
	EXPECT_EQ(a.ptime, 20);
	EXPECT_EQ(a.telephoneEventPt(), 101);
	const sdp::Rtpmap* ev = a.findRtpmap(101);
	ASSERT_NE(ev, nullptr);
	EXPECT_TRUE(ev->telephoneEvent);
	EXPECT_EQ(v(kAudioVideo, ev->fmtp), "0-16");
	EXPECT_EQ(ev->clock, 8000u);
}

TEST(SdpModel, MediaLevelConnectionOverridesSessionLevel)
{
	sdp::Session s;
	sdp::parse(kAudioVideo, s);

	// video has no c= of its own -> session c=; audio has its own -> override (RFC 8866 §5.7)
	auto vid = sdp::connectionAddress(kAudioVideo, sdp::effectiveConnection(s, 0));
	auto aud = sdp::connectionAddress(kAudioVideo, sdp::effectiveConnection(s, 1));
	EXPECT_EQ(v(kAudioVideo, vid.addr), "192.168.1.10");
	EXPECT_EQ(v(kAudioVideo, aud.addr), "192.168.1.77");
	EXPECT_TRUE(aud.isIp4);
	EXPECT_FALSE(aud.isZero);
}

TEST(SdpModel, DirectionScopesPerMediaAndInheritsFromSession)
{
	sdp::Session s;
	sdp::parse(kAudioVideo, s);
	EXPECT_EQ(sdp::effectiveDirection(s, 0), sdp::Direction::SendRecv) << "video inherits the session a=sendrecv";
	EXPECT_EQ(sdp::effectiveDirection(s, 1), sdp::Direction::SendOnly) << "audio's own a=sendonly wins";
	EXPECT_TRUE(sdp::isHold(kAudioVideo, s, 1));
	EXPECT_FALSE(sdp::isHold(kAudioVideo, s, 0));
}

TEST(SdpModel, DefaultDirectionIsSendrecvWhenNothingIsStated)
{
	const std::string body = "v=0\r\no=- 0 0 IN IP4 1.2.3.4\r\ns=-\r\nc=IN IP4 1.2.3.4\r\nt=0 0\r\nm=audio 4000 RTP/AVP 0\r\n";
	sdp::Session s;
	sdp::parse(body, s);
	ASSERT_EQ(s.mediaCount, 1u);
	EXPECT_EQ(sdp::effectiveDirection(s, 0), sdp::Direction::SendRecv);
	EXPECT_FALSE(sdp::isHold(body, s, 0));
}

TEST(SdpModel, LegacyZeroAddressHoldIsRecognised)
{
	// RFC 2543-style hold: no direction attribute at all, c=0.0.0.0. The old
	// four-literal direction test in onReinvite() missed this entirely.
	const std::string body = "v=0\r\no=- 0 0 IN IP4 1.2.3.4\r\ns=-\r\nc=IN IP4 0.0.0.0\r\nt=0 0\r\nm=audio 4000 RTP/AVP 0\r\n";
	sdp::Session s;
	sdp::parse(body, s);
	auto c = sdp::connectionAddress(body, sdp::effectiveConnection(s, 0));
	EXPECT_TRUE(c.isZero);
	EXPECT_TRUE(sdp::isHold(body, s, 0));
	EXPECT_EQ(sdp::effectiveDirection(s, 0), sdp::Direction::SendRecv) << "direction alone would have said 'active'";
}

TEST(SdpModel, BareLfAndBlankLinesParseLikeCrlf)
{
	const std::string body = "v=0\n\no=- 0 0 IN IP4 1.2.3.4\ns=-\nc=IN IP4 1.2.3.4\nt=0 0\nm=audio 4000 RTP/AVP 0 101\na=rtpmap:101 TELEPHONE-EVENT/8000\n";
	sdp::Session s;
	sdp::parse(body, s);
	ASSERT_EQ(s.mediaCount, 1u);
	EXPECT_EQ(s.media[0].port, 4000u);
	EXPECT_EQ(s.media[0].telephoneEventPt(), 101) << "encoding names are case-insensitive (RFC 8866 §6.6)";
	EXPECT_EQ(v(body, s.version), "v=0");
}

TEST(SdpModel, OverflowIsCountedNeverDecodedAndPortSurvives)
{
	// More m= sections and attributes than the model holds. Extra entries are
	// counted in dropped* and the rest of the body still parses.
	std::string body = "v=0\r\no=- 0 0 IN IP4 1.2.3.4\r\ns=-\r\nc=IN IP4 1.2.3.4\r\nt=0 0\r\n";
	for (unsigned i = 0; i < sdp::Limits::kMaxSessionAttrs + 3; ++i) body += "a=x" + std::to_string(i) + ":y\r\n";
	for (unsigned i = 0; i < sdp::Limits::kMaxMedia + 2; ++i)
	{
		body += "m=audio " + std::to_string(4000 + i) + " RTP/AVP 0\r\n";
		for (unsigned k = 0; k < sdp::Limits::kMaxMediaAttrs + 4; ++k) body += "a=q" + std::to_string(k) + "\r\n";
	}
	sdp::Session s;
	sdp::parse(body, s);
	EXPECT_EQ(s.mediaCount, sdp::Limits::kMaxMedia);
	EXPECT_EQ(s.droppedMedia, 2u);
	EXPECT_EQ(s.attrCount, sdp::Limits::kMaxSessionAttrs);
	EXPECT_EQ(s.droppedAttrs, 3u);
	EXPECT_EQ(s.media[0].attrCount, sdp::Limits::kMaxMediaAttrs);
	EXPECT_EQ(s.media[0].droppedAttrs, 4u);
	EXPECT_EQ(s.media[0].port, 4000u);
	EXPECT_EQ(s.media[sdp::Limits::kMaxMedia - 1].port, 4000u + sdp::Limits::kMaxMedia - 1);
}

TEST(SdpModel, AcapFloodIsBoundedByTheLineCapAndDoesNotThrow)
{
	// The T612 attack body shape: one huge a=acap line, then thousands of
	// attribute lines. checkSdp() refuses it on the wire; the model must still
	// be safe on a body that reaches it by another route.
	std::string body = "v=0\r\no=- 0 0 IN IP4 1.2.3.4\r\ns=-\r\nc=IN IP4 1.2.3.4\r\nt=0 0\r\nm=audio 4000 RTP/AVP 0\r\na=acap:1";
	for (int i = 0; i < 200; ++i) body += " acap:1";
	body += "\r\n";
	for (int i = 0; i < 5000; ++i) body += "a=acap:1 acap:1\r\n";
	sdp::Session s;
	sdp::parse(body, s);
	EXPECT_TRUE(s.truncated);
	EXPECT_LE(s.lines, SdpLimits::kMaxLines);
	ASSERT_EQ(s.mediaCount, 1u);
	EXPECT_EQ(s.media[0].port, 4000u);
	EXPECT_EQ(s.media[0].attrCount, sdp::Limits::kMaxMediaAttrs);
}

TEST(SdpModel, ReparseResetsEverythingFromThePreviousBody)
{
	sdp::Session s;
	sdp::parse(kAudioVideo, s);
	ASSERT_EQ(s.mediaCount, 2u);
	const std::string small = "v=0\r\nm=audio 5 RTP/AVP 0\r\n";
	sdp::parse(small, s);
	EXPECT_EQ(s.mediaCount, 1u);
	EXPECT_FALSE(s.connection.present()) << "the old body's session c= must not survive (recycled-slot case)";
	EXPECT_FALSE(s.media[1].line.present());
	EXPECT_EQ(s.media[0].port, 5u);
}

TEST(SdpModel, SpansResolveOnlyAgainstTheirOwnBody)
{
	sdp::Session s;
	sdp::parse(kAudioVideo, s);
	// Applying a span to a shorter body yields an empty view, never a throw.
	EXPECT_TRUE(sdp::view("v=0", s.media[1].line).empty());
}

TEST(SdpModel, RejectedStreamPortAndMultiplexedPortCount)
{
	const std::string body = "v=0\r\nm=video 0 RTP/AVP 96\r\nm=audio 49170/2 RTP/AVP 0\r\n";
	sdp::Session s;
	sdp::parse(body, s);
	ASSERT_EQ(s.mediaCount, 2u);
	EXPECT_EQ(s.media[0].port, 0u);
	EXPECT_EQ(s.media[1].port, 49170u);
	EXPECT_EQ(s.media[1].portCount, 2);
}

TEST(SdpWriter, ReproducesBuildMediaSdpByteForByte)
{
	// The writer replaces three hand-assembled bodies; their exact bytes are what
	// interop was proven against, so pin them.
	sdp::SessionSpec spec;
	spec.originAddr = "192.168.4.1";
	sdp::MediaSpec* m = spec.addMedia();
	m->port = 4000;
	m->add(sdp::FormatSpec{0, "PCMU", 8000, nullptr});
	m->add(sdp::FormatSpec{101, "telephone-event", 8000, "0-15"});
	m->dir = sdp::Direction::SendRecv;
	std::string out;
	sdp::write(spec, out);
	EXPECT_EQ(out,
		"v=0\r\n"
		"o=- 0 0 IN IP4 192.168.4.1\r\n"
		"s=pocketdial-media\r\n"
		"c=IN IP4 192.168.4.1\r\n"
		"t=0 0\r\n"
		"m=audio 4000 RTP/AVP 0 101\r\n"
		"a=rtpmap:0 PCMU/8000\r\n"
		"a=rtpmap:101 telephone-event/8000\r\n"
		"a=fmtp:101 0-15\r\n"
		"a=sendrecv\r\n");
}

TEST(SdpWriter, ReproducesInactiveHoldSdpByteForByte)
{
	sdp::SessionSpec spec;
	spec.originAddr = "10.0.0.2";
	spec.name = "pocket-dial";
	sdp::MediaSpec* m = spec.addMedia();
	m->port = 9;
	m->add(sdp::FormatSpec{0, nullptr, 8000, nullptr});
	m->dir = sdp::Direction::Inactive;
	std::string out;
	sdp::write(spec, out);
	EXPECT_EQ(out,
		"v=0\r\n"
		"o=- 0 0 IN IP4 10.0.0.2\r\n"
		"s=pocket-dial\r\n"
		"c=IN IP4 10.0.0.2\r\n"
		"t=0 0\r\n"
		"m=audio 9 RTP/AVP 0\r\n"
		"a=inactive\r\n");
}

TEST(SdpWriter, WhatItWritesItCanParse)
{
	sdp::SessionSpec spec;
	spec.originAddr = "192.168.4.1";
	sdp::MediaSpec* a = spec.addMedia();
	a->port = 4000;
	a->add(sdp::FormatSpec{0, "PCMU", 8000, nullptr});
	a->add(sdp::FormatSpec{101, "telephone-event", 8000, "0-15"});
	a->dir = sdp::Direction::RecvOnly;
	a->ptime = 20;
	sdp::MediaSpec* vid = spec.addMedia();
	vid->type = "video"; vid->port = 0; vid->add(sdp::FormatSpec{96, nullptr, 90000, nullptr});
	std::string out;
	sdp::write(spec, out);

	sdp::Session s;
	sdp::parse(out, s);
	ASSERT_EQ(s.mediaCount, 2u);
	EXPECT_EQ(s.media[0].port, 4000u);
	EXPECT_EQ(s.media[0].ptime, 20);
	EXPECT_EQ(s.media[0].telephoneEventPt(), 101);
	EXPECT_EQ(sdp::effectiveDirection(s, 0), sdp::Direction::RecvOnly);
	EXPECT_EQ(s.media[1].type, sdp::MediaType::Video);
	EXPECT_EQ(s.media[1].port, 0u);
}
