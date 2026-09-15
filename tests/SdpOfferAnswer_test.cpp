// Issue #196: RFC 3264 offer/answer on the sdp:: model. The board answering a
// phone's offer (buildAnswer), the admission check for a relayed answer
// (validateAnswer), and hold detection (holdRequested).

#include <gtest/gtest.h>

#include <string>

#include "Sdp.hpp"
#include "SdpOfferAnswer.hpp"

namespace
{
	std::string offerWith(const std::string& mediaLines)
	{
		return "v=0\r\no=bob 1 1 IN IP4 10.0.0.9\r\ns=-\r\nc=IN IP4 10.0.0.9\r\nt=0 0\r\n" + mediaLines;
	}

	struct Parsed
	{
		std::string body;
		sdp::Session s;
		explicit Parsed(std::string b) : body(std::move(b)) { sdp::parse(body, s); }
	};

	sdp::AnswerParams params(sdp::Direction want = sdp::Direction::SendRecv)
	{
		sdp::AnswerParams p;
		p.localIp = "192.168.4.1";
		p.audioPort = 4000;
		p.want = want;
		return p;
	}
}

TEST(SdpOfferAnswer, PcmaFirstOfferGetsPcmaAnsweredWhenTheBoardSpeaksIt)
{
	// The issue's headline case, in the direction the board CAN honour: the
	// phone prefers PCMA and we intersect in the offer's order (§6.1).
	Parsed o(offerWith("m=audio 6000 RTP/AVP 8 0 101\r\na=rtpmap:8 PCMA/8000\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-16\r\n"));
	sdp::LocalCaps caps;
	caps.audioPts[0] = 0; caps.audioPts[1] = 8; caps.audioCount = 2;
	std::string out;
	auto r = sdp::buildAnswer(o.body, o.s, caps, params(), out);

	EXPECT_TRUE(r.acceptedAudio);
	EXPECT_EQ(r.audioIndex, 0);
	EXPECT_EQ(r.telephoneEventPt, 101);
	EXPECT_NE(out.find("m=audio 4000 RTP/AVP 8 0 101\r\n"), std::string::npos) << out;
	EXPECT_NE(out.find("a=fmtp:101 0-16\r\n"), std::string::npos) << "echo the OFFERED event range, never our own: " << out;
	EXPECT_NE(out.find("a=sendrecv\r\n"), std::string::npos) << out;
	EXPECT_NE(out.find("c=IN IP4 192.168.4.1\r\n"), std::string::npos) << out;
}

TEST(SdpOfferAnswer, PcmaOnlyPhoneAgainstPcmuOnlyBoardIsRejectedNotLiedTo)
{
	// The bug as shipped: a PCMA-only phone used to get a PCMU answer it cannot
	// play. The honest RFC 3264 answer is a port-0 stream, and the caller 488s.
	Parsed o(offerWith("m=audio 6000 RTP/AVP 8\r\na=rtpmap:8 PCMA/8000\r\n"));
	std::string out;
	auto r = sdp::buildAnswer(o.body, o.s, sdp::LocalCaps::pcmuOnly(), params(), out);
	EXPECT_FALSE(r.acceptedAudio);
	EXPECT_NE(out.find("m=audio 0 RTP/AVP 8\r\n"), std::string::npos) << out;
	EXPECT_EQ(out.find("PCMU"), std::string::npos) << "must not advertise a codec the offer lacked: " << out;
}

TEST(SdpOfferAnswer, VideoStreamIsRejectedWithPortZeroNotDropped)
{
	// §6: the answer has one m= per offered m=, same order. The old builder
	// ignored the video line, so the phone's video port received our audio.
	Parsed o(offerWith("m=video 51372 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\nm=audio 49170 RTP/AVP 0 101\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:101 telephone-event/8000\r\n"));
	std::string out;
	auto r = sdp::buildAnswer(o.body, o.s, sdp::LocalCaps::pcmuOnly(), params(), out);
	EXPECT_TRUE(r.acceptedAudio);
	EXPECT_EQ(r.audioIndex, 1);
	const size_t vpos = out.find("m=video 0 RTP/AVP 96\r\n");
	const size_t apos = out.find("m=audio 4000 RTP/AVP 0 101\r\n");
	ASSERT_NE(vpos, std::string::npos) << out;
	ASSERT_NE(apos, std::string::npos) << out;
	EXPECT_LT(vpos, apos) << "same order as the offer";

	sdp::Session a;
	sdp::parse(out, a);
	EXPECT_EQ(sdp::validateAnswer(o.s, a), sdp::AnswerVerdict::Ok) << "our own answer must pass our own validator";
}

TEST(SdpOfferAnswer, DirectionIsTheComplementOfTheOfferLimitedByWhatWeWant)
{
	using D = sdp::Direction;
	EXPECT_EQ(sdp::answerDirection(D::SendRecv, D::SendRecv), D::SendRecv);
	EXPECT_EQ(sdp::answerDirection(D::SendOnly, D::SendRecv), D::RecvOnly);
	EXPECT_EQ(sdp::answerDirection(D::RecvOnly, D::SendRecv), D::SendOnly);
	EXPECT_EQ(sdp::answerDirection(D::Inactive, D::SendRecv), D::Inactive);
	// A tone/MoH leg wants to send only:
	EXPECT_EQ(sdp::answerDirection(D::SendRecv, D::SendOnly), D::SendOnly);
	EXPECT_EQ(sdp::answerDirection(D::RecvOnly, D::SendOnly), D::SendOnly);
	EXPECT_EQ(sdp::answerDirection(D::SendOnly, D::SendOnly), D::Inactive) << "they only send, we only send: nothing flows";
	EXPECT_EQ(sdp::answerDirection(D::SendRecv, D::Inactive), D::Inactive);
}

TEST(SdpOfferAnswer, HoldOfferIsAnsweredRecvonly)
{
	Parsed o(offerWith("m=audio 6000 RTP/AVP 0\r\na=sendonly\r\n"));
	std::string out;
	auto r = sdp::buildAnswer(o.body, o.s, sdp::LocalCaps::pcmuOnly(), params(), out);
	EXPECT_EQ(r.dir, sdp::Direction::RecvOnly);
	EXPECT_NE(out.find("a=recvonly\r\n"), std::string::npos) << out;
}

TEST(SdpOfferAnswer, ValidateAnswerCatchesWhatTheRelayUsedToPassThrough)
{
	Parsed o(offerWith("m=audio 6000 RTP/AVP 0 8 101\r\nm=video 7000 RTP/AVP 96\r\n"));

	Parsed good(offerWith("m=audio 6002 RTP/AVP 8 101\r\nm=video 0 RTP/AVP 96\r\n"));
	EXPECT_EQ(sdp::validateAnswer(o.s, good.s), sdp::AnswerVerdict::Ok);

	Parsed fewer(offerWith("m=audio 6002 RTP/AVP 8\r\n"));
	EXPECT_EQ(sdp::validateAnswer(o.s, fewer.s), sdp::AnswerVerdict::MediaCountMismatch);

	Parsed reordered(offerWith("m=video 7002 RTP/AVP 96\r\nm=audio 6002 RTP/AVP 8\r\n"));
	EXPECT_EQ(sdp::validateAnswer(o.s, reordered.s), sdp::AnswerVerdict::MediaTypeMismatch);

	Parsed invented(offerWith("m=audio 6002 RTP/AVP 18\r\nm=video 0 RTP/AVP 96\r\n"));
	EXPECT_EQ(sdp::validateAnswer(o.s, invented.s), sdp::AnswerVerdict::FormatNotOffered)
		<< "G.729 was never offered; a relayed 200 OK carrying it must not reach the caller";

	Parsed rejectedWithOddFmt(offerWith("m=audio 0 RTP/AVP 18\r\nm=video 0 RTP/AVP 96\r\n"));
	EXPECT_EQ(sdp::validateAnswer(o.s, rejectedWithOddFmt.s), sdp::AnswerVerdict::Ok)
		<< "a port-0 stream's formats are unconstrained (§6)";
}

TEST(SdpOfferAnswer, HoldRequestedCoversDirectionAndLegacyZeroAddress)
{
	Parsed sendonly(offerWith("m=audio 6000 RTP/AVP 0\r\na=sendonly\r\n"));
	Parsed inactive(offerWith("m=audio 6000 RTP/AVP 0\r\na=inactive\r\n"));
	Parsed sessionLevel("v=0\r\no=- 0 0 IN IP4 1.2.3.4\r\ns=-\r\nc=IN IP4 1.2.3.4\r\nt=0 0\r\na=sendonly\r\nm=audio 6000 RTP/AVP 0\r\n");
	Parsed zero("v=0\r\no=- 0 0 IN IP4 1.2.3.4\r\ns=-\r\nc=IN IP4 0.0.0.0\r\nt=0 0\r\nm=audio 6000 RTP/AVP 0\r\n");
	Parsed mediaZero("v=0\r\no=- 0 0 IN IP4 1.2.3.4\r\ns=-\r\nc=IN IP4 1.2.3.4\r\nt=0 0\r\nm=audio 6000 RTP/AVP 0\r\nc=IN IP4 0.0.0.0\r\n");
	Parsed active(offerWith("m=audio 6000 RTP/AVP 0\r\na=sendrecv\r\n"));
	Parsed videoHeldAudioActive(offerWith("m=video 7000 RTP/AVP 96\r\na=sendonly\r\nm=audio 6000 RTP/AVP 0\r\n"));

	EXPECT_TRUE(sdp::holdRequested(sendonly.body, sendonly.s));
	EXPECT_TRUE(sdp::holdRequested(inactive.body, inactive.s));
	EXPECT_TRUE(sdp::holdRequested(sessionLevel.body, sessionLevel.s)) << "session-level a=sendonly applies to the audio m=";
	EXPECT_TRUE(sdp::holdRequested(zero.body, zero.s));
	EXPECT_TRUE(sdp::holdRequested(mediaZero.body, mediaZero.s));
	EXPECT_FALSE(sdp::holdRequested(active.body, active.s));
	EXPECT_FALSE(sdp::holdRequested(videoHeldAudioActive.body, videoHeldAudioActive.s))
		<< "hold is judged on the AUDIO stream, not whichever m= comes first";
}
