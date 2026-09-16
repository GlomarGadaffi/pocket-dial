// SipSdpSectionSelection_test.cpp — issue #253.
//
// getMedia()/setMedia() disagree about which m= section they mean on a
// multi-section body (last vs. first respectively), and that disagreement is
// deliberately preserved for backward compatibility — see SipSdpMessage.cpp's
// own comments on both. The real fix isn't to make them agree; it's to let a
// caller name the section it means instead of relying on either implicit
// default. These tests cover the new explicit-section API:
// firstAudioSection(), getRtpPort(int), getConnectionInformation(int).
//
// No offer this PBX currently handles has more than one m= section (the
// interop harness disables video, every fixture is audio-only, the
// hardphones in use are audio-only), so this closes a trap for the first
// multi-section offer rather than fixing a live bug — see the issue.

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

	// The exact shape #253 is about: audio+video, so "first" and "last" section
	// disagree. Session-level c= is deliberately generic; each media section
	// carries its OWN connection so a test that reads the wrong section reads
	// the wrong address, not a coincidentally-identical one.
	const char* kAudioThenVideo =
		"v=0\r\n"
		"o=- 111 111 IN IP4 192.168.1.10\r\n"
		"s=call\r\n"
		"c=IN IP4 192.168.1.10\r\n"
		"t=0 0\r\n"
		"m=audio 4000 RTP/AVP 0\r\n"
		"c=IN IP4 192.168.1.50\r\n"
		"a=rtpmap:0 PCMU/8000\r\n"
		"m=video 4002 RTP/AVP 96\r\n"
		"c=IN IP4 192.168.1.60\r\n"
		"a=rtpmap:96 H264/90000\r\n";

	// Deliberately the OPPOSITE order, so a test that assumes "first section"
	// means "index 0" rather than "the first one whose typeName is audio"
	// would fail here and pass on kAudioThenVideo.
	const char* kVideoThenAudio =
		"v=0\r\n"
		"o=- 222 222 IN IP4 192.168.1.10\r\n"
		"s=call\r\n"
		"c=IN IP4 192.168.1.10\r\n"
		"t=0 0\r\n"
		"m=video 4002 RTP/AVP 96\r\n"
		"c=IN IP4 192.168.1.60\r\n"
		"a=rtpmap:96 H264/90000\r\n"
		"m=audio 4000 RTP/AVP 0\r\n"
		"c=IN IP4 192.168.1.50\r\n"
		"a=rtpmap:0 PCMU/8000\r\n";

	const char* kVideoOnly =
		"v=0\r\n"
		"o=- 333 333 IN IP4 192.168.1.10\r\n"
		"s=call\r\n"
		"c=IN IP4 192.168.1.10\r\n"
		"t=0 0\r\n"
		"m=video 4002 RTP/AVP 96\r\n"
		"a=rtpmap:96 H264/90000\r\n";

	const char* kAudioOnly =
		"v=0\r\n"
		"o=- 444 444 IN IP4 192.168.1.10\r\n"
		"s=call\r\n"
		"c=IN IP4 192.168.1.10\r\n"
		"t=0 0\r\n"
		"m=audio 5000 RTP/AVP 0\r\n"
		"a=rtpmap:0 PCMU/8000\r\n";
}

TEST(SipSdpSectionSelection, FirstAudioSectionFindsAudioRegardlessOfPosition)
{
	SipSdpMessage audioFirst(inviteWith(kAudioThenVideo), localAddr());
	EXPECT_EQ(audioFirst.firstAudioSection(), 0);

	SipSdpMessage videoFirst(inviteWith(kVideoThenAudio), localAddr());
	EXPECT_EQ(videoFirst.firstAudioSection(), 1)
		<< "audio is section 1 here, not 0 -- a fix that assumed \"first "
		   "section\" meant index 0 would get this wrong";
}

TEST(SipSdpSectionSelection, FirstAudioSectionIsMinusOneWithNoAudio)
{
	SipSdpMessage m(inviteWith(kVideoOnly), localAddr());
	EXPECT_EQ(m.firstAudioSection(), -1);
}

TEST(SipSdpSectionSelection, GetRtpPortReadsTheNamedSectionNotTheLastOne)
{
	// This is the actual #253 disagreement: the no-arg getRtpPort() would
	// return the VIDEO port here (4002, the last section) -- the section-aware
	// overload must return the AUDIO port (4000) when explicitly asked for it.
	SipSdpMessage m(inviteWith(kAudioThenVideo), localAddr());
	const int audioSection = m.firstAudioSection();
	ASSERT_EQ(audioSection, 0);

	EXPECT_EQ(m.getRtpPort(audioSection), 4000);
	EXPECT_EQ(m.getRtpPort(1), 4002) << "section 1 (video) is still readable directly";
	EXPECT_NE(m.getRtpPort(audioSection), m.getRtpPort())
		<< "the no-arg accessor (last section) and the explicit audio section "
		   "must disagree on this body -- if they don't, this test stopped "
		   "proving anything";
}

TEST(SipSdpSectionSelection, GetConnectionInformationReadsTheNamedSectionsOwnAddress)
{
	SipSdpMessage m(inviteWith(kAudioThenVideo), localAddr());
	const int audioSection = m.firstAudioSection();
	ASSERT_EQ(audioSection, 0);

	EXPECT_EQ(std::string(m.getConnectionInformation(audioSection)), "c=IN IP4 192.168.1.50");
	EXPECT_EQ(std::string(m.getConnectionInformation(1)), "c=IN IP4 192.168.1.60");
}

TEST(SipSdpSectionSelection, OutOfRangeSectionIsSafeNotAnAssert)
{
	SipSdpMessage m(inviteWith(kAudioOnly), localAddr());
	EXPECT_EQ(m.getRtpPort(-1), 0);
	EXPECT_EQ(m.getRtpPort(5), 0);
	EXPECT_TRUE(m.getConnectionInformation(-1).empty());
	EXPECT_TRUE(m.getConnectionInformation(5).empty());
}

TEST(SipSdpSectionSelection, SingleSectionBodyAgreesWithTheLegacyNoArgAccessors)
{
	// The whole reason this was safe to leave unmigrated until now: with one
	// section, "first" and "last" name the same line, so the new and old
	// accessors must return identical answers on every body this PBX has
	// actually handled in production so far.
	SipSdpMessage m(inviteWith(kAudioOnly), localAddr());
	const int audioSection = m.firstAudioSection();
	ASSERT_EQ(audioSection, 0);

	EXPECT_EQ(m.getRtpPort(audioSection), m.getRtpPort());
	EXPECT_EQ(std::string(m.getConnectionInformation(audioSection)),
		std::string(m.getConnectionInformation()));
}
