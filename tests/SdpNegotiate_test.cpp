// SdpNegotiate_test.cpp — SipMessage::filterAudioCodecs / offersSupportedAudio.
//
// The relay codec policy that replaced the blind enforceG711() rewrite on the
// peer-to-peer legs. What must hold:
//   * the endpoint's payload ORDER is preserved (offerer preference wins);
//   * only unsupported payloads are dropped, together with their a=rtpmap /
//     a=fmtp lines -- nothing is ever ADDED to an offer;
//   * G.722 (PT 9) survives on a wideband leg and is dropped on a narrowband one;
//   * telephone-event survives whatever its (dynamic) payload number;
//   * an offer with no audio codec left is reported (false) and left untouched,
//     so onInvite can answer 488 instead of advertising phantom payloads;
//   * Content-Length tracks the body (the 777/999 bug class).

#include <gtest/gtest.h>

#include <string>

#include "SipMessage.hpp"

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#else
#include <arpa/inet.h>
#endif

namespace
{
	std::string inviteWith(const std::string& body)
	{
		return
			"INVITE sip:600@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP 192.168.7.50:5060;branch=z9hG4bKsdp\r\n"
			"From: <sip:500@server>;tag=f1\r\n"
			"To: <sip:600@server>\r\n"
			"Call-ID: sdp-1\r\n"
			"CSeq: 1 INVITE\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
	}

	std::string sdp(const std::string& mLine, const std::string& attrs)
	{
		return
			"v=0\r\n"
			"o=- 0 0 IN IP4 192.168.7.50\r\n"
			"s=-\r\n"
			"c=IN IP4 192.168.7.50\r\n"
			"t=0 0\r\n" + mLine + "\r\n" + attrs;
	}

	std::string contentLengthOf(const SipMessage& m)
	{
		std::string raw = m.toString();
		size_t p = raw.find("Content-Length: ");
		size_t e = raw.find("\r\n", p);
		return raw.substr(p + 16, e - p - 16);
	}

	SipMessage make(const std::string& body)
	{
		sockaddr_in src{};
		return SipMessage(inviteWith(body), src);
	}
}

TEST(SdpNegotiate, PreservesOfferOrderAndKeepsWidebandOnWidebandLeg)
{
	SipMessage m = make(sdp("m=audio 10000 RTP/AVP 9 0 8 101",
	                        "a=rtpmap:9 G722/8000\r\n"
	                        "a=rtpmap:0 PCMU/8000\r\n"
	                        "a=rtpmap:8 PCMA/8000\r\n"
	                        "a=rtpmap:101 telephone-event/8000\r\n"
	                        "a=fmtp:101 0-15\r\n"
	                        "a=sendrecv\r\n"));
	const std::string before(m.getBody());
	EXPECT_TRUE(m.offersSupportedAudio(true));
	EXPECT_TRUE(m.filterAudioCodecs(true));
	EXPECT_EQ(std::string(m.getBody()), before) << "nothing to drop -> byte-identical body";
	EXPECT_NE(std::string(m.getBody()).find("m=audio 10000 RTP/AVP 9 0 8 101"), std::string::npos)
		<< "G.722-first preference must survive, in order";
}

TEST(SdpNegotiate, NarrowbandLegDropsG722AndItsRtpmap)
{
	SipMessage m = make(sdp("m=audio 10000 RTP/AVP 9 0 101",
	                        "a=rtpmap:9 G722/8000\r\n"
	                        "a=rtpmap:0 PCMU/8000\r\n"
	                        "a=rtpmap:101 telephone-event/8000\r\n"
	                        "a=fmtp:101 0-15\r\n"));
	EXPECT_TRUE(m.filterAudioCodecs(false));
	const std::string body(m.getBody());
	EXPECT_NE(body.find("m=audio 10000 RTP/AVP 0 101\r\n"), std::string::npos) << body;
	EXPECT_EQ(body.find("a=rtpmap:9 "), std::string::npos) << "rtpmap for the dropped PT must go";
	EXPECT_NE(body.find("a=rtpmap:0 PCMU/8000"), std::string::npos);
	EXPECT_NE(body.find("a=fmtp:101 0-15"), std::string::npos) << "kept PT keeps its fmtp";
	EXPECT_EQ(contentLengthOf(m), std::to_string(body.size())) << "Content-Length resynced";
}

TEST(SdpNegotiate, DynamicPayloadsDroppedWithFmtpTelephoneEventKeptByName)
{
	// Opus (dynamic 96 with fmtp) + G.722 + telephone-event on a dynamic PT 120.
	SipMessage m = make(sdp("m=audio 10000 RTP/AVP 96 9 120",
	                        "a=rtpmap:96 opus/48000/2\r\n"
	                        "a=fmtp:96 useinbandfec=1\r\n"
	                        "a=rtpmap:9 G722/8000\r\n"
	                        "a=rtpmap:120 telephone-event/8000\r\n"
	                        "a=fmtp:120 0-16\r\n"));
	EXPECT_TRUE(m.filterAudioCodecs(true));
	const std::string body(m.getBody());
	EXPECT_NE(body.find("m=audio 10000 RTP/AVP 9 120\r\n"), std::string::npos) << body;
	EXPECT_EQ(body.find("opus"), std::string::npos);
	EXPECT_EQ(body.find("a=fmtp:96"), std::string::npos);
	EXPECT_NE(body.find("a=rtpmap:120 telephone-event/8000"), std::string::npos);
	EXPECT_NE(body.find("a=fmtp:120 0-16"), std::string::npos);
}

TEST(SdpNegotiate, NoCommonCodecReportsFalseAndLeavesBodyUntouched)
{
	SipMessage m = make(sdp("m=audio 10000 RTP/AVP 96 101",
	                        "a=rtpmap:96 opus/48000/2\r\n"
	                        "a=rtpmap:101 telephone-event/8000\r\n"));
	const std::string before(m.getBody());
	EXPECT_FALSE(m.offersSupportedAudio(true)) << "telephone-event alone is not audio";
	EXPECT_FALSE(m.filterAudioCodecs(true));
	EXPECT_EQ(std::string(m.getBody()), before);
	EXPECT_EQ(contentLengthOf(m), std::to_string(before.size()));
}

TEST(SdpNegotiate, G722OnlyIsAudioOnWidebandButNotNarrowband)
{
	SipMessage m = make(sdp("m=audio 10000 RTP/AVP 9", "a=rtpmap:9 G722/8000\r\n"));
	EXPECT_TRUE(m.offersSupportedAudio(true));
	EXPECT_FALSE(m.offersSupportedAudio(false));
}

TEST(SdpNegotiate, NeverAddsPayloadsTheEndpointDidNotOffer)
{
	// PCMA-only phone: the old enforceG711() would have written "0 8 101" here.
	SipMessage m = make(sdp("m=audio 10000 RTP/AVP 8", "a=rtpmap:8 PCMA/8000\r\n"));
	EXPECT_TRUE(m.filterAudioCodecs(true));
	EXPECT_NE(std::string(m.getBody()).find("m=audio 10000 RTP/AVP 8\r\n"), std::string::npos);
}

TEST(SdpNegotiate, NoAudioMediaLineIsANoOp)
{
	SipMessage m = make("v=0\r\no=- 0 0 IN IP4 1.2.3.4\r\ns=-\r\nt=0 0\r\n");
	EXPECT_TRUE(m.offersSupportedAudio(false));
	EXPECT_TRUE(m.filterAudioCodecs(false));
}

TEST(SdpNegotiate, EnforceG711StillPinsServerLegs)
{
	SipMessage m = make(sdp("m=audio 10000 RTP/AVP 9 0", "a=rtpmap:9 G722/8000\r\n"));
	m.enforceG711();
	EXPECT_NE(std::string(m.getBody()).find("m=audio 10000 RTP/AVP 0 8 101"), std::string::npos);
}

// ── Issue #304: allowPcma -- nothing in this codebase decodes A-law, so a
// handful of server-terminated legs (777, anchor, and #304's fix) must be
// able to reject/strip PCMA specifically, distinct from allowWideband. ──────

TEST(SdpNegotiate, AllowPcmaDefaultsTrueSoEveryExistingCallSiteIsUnaffected)
{
	SipMessage m = make(sdp("m=audio 10000 RTP/AVP 0 8 101",
	                        "a=rtpmap:0 PCMU/8000\r\n"
	                        "a=rtpmap:8 PCMA/8000\r\n"
	                        "a=rtpmap:101 telephone-event/8000\r\n"));
	const std::string before(m.getBody());
	EXPECT_TRUE(m.offersSupportedAudio(false));   // no allowPcma arg -> true
	EXPECT_TRUE(m.filterAudioCodecs(false));
	EXPECT_EQ(std::string(m.getBody()), before) << "PCMA kept by default, nothing rewritten";
}

TEST(SdpNegotiate, PcmaOnlyOfferReportsUnsupportedWhenPcmaDisallowed)
{
	SipMessage m = make(sdp("m=audio 10000 RTP/AVP 8", "a=rtpmap:8 PCMA/8000\r\n"));
	EXPECT_FALSE(m.offersSupportedAudio(/*allowWideband=*/false, /*allowPcma=*/false));
	EXPECT_FALSE(m.filterAudioCodecs(/*allowWideband=*/false, /*allowPcma=*/false))
		<< "no codec would survive -- body must be left untouched, same as any other 488 case";
}

TEST(SdpNegotiate, DualCodecOfferKeepsOnlyPcmuWhenPcmaDisallowed)
{
	SipMessage m = make(sdp("m=audio 10000 RTP/AVP 0 8 101",
	                        "a=rtpmap:0 PCMU/8000\r\n"
	                        "a=rtpmap:8 PCMA/8000\r\n"
	                        "a=rtpmap:101 telephone-event/8000\r\n"));
	EXPECT_TRUE(m.offersSupportedAudio(/*allowWideband=*/false, /*allowPcma=*/false))
		<< "PCMU alone is still enough to admit the call";
	EXPECT_TRUE(m.filterAudioCodecs(/*allowWideband=*/false, /*allowPcma=*/false));
	const std::string body(m.getBody());
	EXPECT_NE(body.find("m=audio 10000 RTP/AVP 0 101\r\n"), std::string::npos) << body;
	EXPECT_EQ(body.find("a=rtpmap:8 "), std::string::npos)
		<< "rtpmap for the dropped PCMA payload must go";
}

TEST(SdpNegotiate, AllowPcmaAndAllowWidebandAreIndependent)
{
	// A caller offering all three: PCMU survives regardless; G.722 and PCMA
	// are each gated by their OWN, independent parameter.
	SipMessage m = make(sdp("m=audio 10000 RTP/AVP 9 0 8",
	                        "a=rtpmap:9 G722/8000\r\n"
	                        "a=rtpmap:0 PCMU/8000\r\n"
	                        "a=rtpmap:8 PCMA/8000\r\n"));
	EXPECT_TRUE(m.filterAudioCodecs(/*allowWideband=*/true, /*allowPcma=*/false));
	const std::string body(m.getBody());
	EXPECT_NE(body.find("m=audio 10000 RTP/AVP 9 0\r\n"), std::string::npos)
		<< "wideband kept, PCMA dropped: " << body;
}
