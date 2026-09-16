// ParseCallerRtp_section_test.cpp — issue #253.
//
// RequestsHandler::parseCallerRtp() is the one production caller of
// SipSdpMessage's no-arg getRtpPort()/getConnectionInformation() (confirmed by
// grep -- nothing else outside SipSdpMessage.cpp calls either). Those
// accessors answer "which section?" implicitly and disagree with each other
// on a multi-section body (getMedia() returns the LAST section, setMedia()
// writes the FIRST) -- see SipSdpMessage.cpp's own comments. This file proves
// parseCallerRtp() itself now names the section explicitly (the first AUDIO
// section) instead of inheriting either implicit default.
//
// No offer this PBX currently handles has more than one m= section (see the
// issue), so this is closing a trap, not fixing a live production bug: every
// existing caller of parseCallerRtp() sees byte-identical behaviour on every
// body it has ever actually been given. The last test below pins that.
//
// NOTE: getMessageFromPool() draws from a process-global pool shared with
// every other test in this binary -- release what's held before the test
// ends, same discipline as RequestsHandler_pool_test.cpp.

#include <gtest/gtest.h>

#include "RequestsHandler.hpp"

#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

namespace
{
	sockaddr_in srcAddr()
	{
		sockaddr_in a{};
		a.sin_family = AF_INET;
		a.sin_port   = htons(5060);
		::inet_pton(AF_INET, "192.168.9.10", &a.sin_addr);
		return a;
	}

	std::string inviteWith(const std::string& body)
	{
		return "INVITE sip:440@server SIP/2.0\r\n"
		       "Via: SIP/2.0/UDP 192.168.9.10:5060;branch=z9hG4bK1\r\n"
		       "From: <sip:100@server>;tag=a\r\n"
		       "To: <sip:440@server>\r\n"
		       "Call-ID: parsecallerrtp-section-test\r\n"
		       "CSeq: 1 INVITE\r\n"
		       "Content-Type: application/sdp\r\n"
		       "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
	}

	// Audio's own c= and port are deliberately different from video's, so a
	// test that reads the wrong section gets the wrong (not coincidentally
	// matching) answer for both fields at once.
	const char* kAudioThenVideo =
		"v=0\r\n"
		"o=- 1 1 IN IP4 192.168.9.10\r\n"
		"s=call\r\n"
		"c=IN IP4 192.168.9.10\r\n"
		"t=0 0\r\n"
		"m=audio 6000 RTP/AVP 0\r\n"
		"c=IN IP4 192.168.9.50\r\n"
		"a=rtpmap:0 PCMU/8000\r\n"
		"m=video 6002 RTP/AVP 96\r\n"
		"c=IN IP4 192.168.9.60\r\n"
		"a=rtpmap:96 H264/90000\r\n";

	const char* kVideoOnly =
		"v=0\r\n"
		"o=- 2 2 IN IP4 192.168.9.10\r\n"
		"s=call\r\n"
		"c=IN IP4 192.168.9.10\r\n"
		"t=0 0\r\n"
		"m=video 6002 RTP/AVP 96\r\n"
		"a=rtpmap:96 H264/90000\r\n";

	const char* kAudioOnly =
		"v=0\r\n"
		"o=- 3 3 IN IP4 192.168.9.10\r\n"
		"s=call\r\n"
		"c=IN IP4 192.168.9.10\r\n"
		"t=0 0\r\n"
		"m=audio 7000 RTP/AVP 0\r\n"
		"c=IN IP4 192.168.9.51\r\n"
		"a=rtpmap:0 PCMU/8000\r\n";
}

TEST(ParseCallerRtpSection, PicksTheAudioSectionNotTheLastSectionOnAnAudioVideoOffer)
{
	// Before #253: getRtpPort()/getConnectionInformation() with no argument
	// each report the LAST section -- video here -- so a caller offering
	// audio+video would have had its RTP aimed at the VIDEO port and address.
	auto invite = RequestsHandler::getMessageFromPool(inviteWith(kAudioThenVideo), srcAddr());
	ASSERT_TRUE(invite);

	std::string ip;
	uint16_t port = 0;
	const bool ok = RequestsHandler::parseCallerRtp(invite, ip, port);

	EXPECT_TRUE(ok);
	EXPECT_EQ(port, 6000) << "must be the AUDIO port, not 6002 (video, the last section)";
	EXPECT_EQ(ip, "192.168.9.50") << "must be the AUDIO section's own c=, not video's";

	invite.reset();
}

TEST(ParseCallerRtpSection, RefusesAVideoOnlyOfferRatherThanTreatingItAsAudio)
{
	// Before #253 this would have silently used the video section's port/c=
	// as if it were audio, since getRtpPort()/getConnectionInformation() don't
	// know or care what typeName a section has. A caller here explicitly
	// wants audio; an offer with no audio section at all should be refused,
	// not quietly misattributed to whatever the last (or only) section is.
	auto invite = RequestsHandler::getMessageFromPool(inviteWith(kVideoOnly), srcAddr());
	ASSERT_TRUE(invite);

	std::string ip;
	uint16_t port = 0;
	const bool ok = RequestsHandler::parseCallerRtp(invite, ip, port);

	EXPECT_FALSE(ok) << "no audio section exists; parseCallerRtp must not "
	                    "substitute the video section for it";

	invite.reset();
}

TEST(ParseCallerRtpSection, SingleAudioSectionOfferIsUnaffected)
{
	// The reason this was safe to leave unmigrated for as long as it was:
	// every real offer this PBX has ever handled is single-section, where
	// "the first audio section" and "the last section" (the old implicit
	// choice) name the exact same line. This is the regression pin for every
	// existing production caller of parseCallerRtp().
	auto invite = RequestsHandler::getMessageFromPool(inviteWith(kAudioOnly), srcAddr());
	ASSERT_TRUE(invite);

	std::string ip;
	uint16_t port = 0;
	const bool ok = RequestsHandler::parseCallerRtp(invite, ip, port);

	EXPECT_TRUE(ok);
	EXPECT_EQ(port, 7000);
	EXPECT_EQ(ip, "192.168.9.51");

	invite.reset();
}
