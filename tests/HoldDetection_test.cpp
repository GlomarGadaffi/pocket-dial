// HoldDetection_test.cpp — issue #263.
//
// sdp::isHold() (SdpModel.cpp) shipped with #255, fully host-tested, and had
// zero production callers: all three real hold/resume sites called the older
// SipMessage::getSdpDirection() instead, which scans for a=sendonly/inactive
// and never looks at the connection address at all. Older, RFC 2543-era
// phones signal hold by blackholing the media address (c=IN IP4 0.0.0.0)
// without changing the direction attribute, so that class of hold was never
// detected in production no matter how correctly the model itself parsed it.
//
// These drive the two non-anchor sites end to end through
// RequestsHandler::handle() -- the anchor site (answerAnchorReinvite, #218)
// already has its own hold/resume tests in AnchorRouting_test.cpp, which is
// where this issue's third site's coverage lives, right beside them.
//
// Covers: a session-level "a=sendrecv" offer whose AUDIO section blackholes
// its connection address is still detected as hold, through both onReinvite()
// (a plain re-INVITE) and onUpdate() (RFC 3311); and that a recvonly offer is
// STILL treated as hold after the isHold() swap -- this PBX has always
// treated recvonly as hold at all three sites even though RFC 3264 s8.4
// itself does not call it that, and the fix keeps that as an explicit
// decision rather than silently dropping it as a side effect of switching
// detectors (isHold() alone would not catch it).

#include <gtest/gtest.h>

#include <string>
#include <utility>
#include <vector>

#include "RequestsHandler.hpp"
#include "SipSdpMessage.hpp"

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#else
#include <arpa/inet.h>
#endif

namespace
{
	constexpr const char* kServerIp = "192.168.50.1";

	sockaddr_in addrFor(const std::string& ip, uint16_t port = 5060)
	{
		sockaddr_in a{};
		a.sin_family = AF_INET;
		a.sin_addr.s_addr = inet_addr(ip.c_str());
		a.sin_port = htons(port);
		return a;
	}

	std::shared_ptr<SipMessage> makeRegister(const std::string& ext, const std::string& ip,
	                                          const std::string& callId)
	{
		std::string raw =
			"REGISTER sip:server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + ip + ":5060;branch=z9hG4bKr" + callId + "\r\n"
			"From: <sip:" + ext + "@server>;tag=rt" + callId + "\r\n"
			"To: <sip:" + ext + "@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 REGISTER\r\n"
			"Contact: <sip:" + ext + "@" + ip + ":5060>;expires=3600\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addrFor(ip));
	}

	std::string plainSdpBody(const std::string& ip)
	{
		return
			"v=0\r\n"
			"o=- 0 0 IN IP4 " + ip + "\r\n"
			"s=-\r\n"
			"c=IN IP4 " + ip + "\r\n"
			"t=0 0\r\n"
			"m=audio 10000 RTP/AVP 0\r\n"
			"a=rtpmap:0 PCMU/8000\r\n";
	}

	// The legacy RFC 2543 hold shape this issue is about: session level says
	// "a=sendrecv" -- an explicit, unambiguous "not holding" by direction --
	// while the AUDIO section's OWN connection address is blackholed. A
	// detector that only reads direction (getSdpDirection(), pre-#263) must
	// call this an active call; sdp::isHold() must not.
	std::string legacyHoldSdpBody(const std::string& ip)
	{
		return
			"v=0\r\n"
			"o=- 0 0 IN IP4 " + ip + "\r\n"
			"s=-\r\n"
			"c=IN IP4 " + ip + "\r\n"
			"t=0 0\r\n"
			"a=sendrecv\r\n"
			"m=audio 10000 RTP/AVP 0\r\n"
			"c=IN IP4 0.0.0.0\r\n"
			"a=rtpmap:0 PCMU/8000\r\n";
	}

	std::string recvonlySdpBody(const std::string& ip)
	{
		return
			"v=0\r\n"
			"o=- 0 0 IN IP4 " + ip + "\r\n"
			"s=-\r\n"
			"c=IN IP4 " + ip + "\r\n"
			"t=0 0\r\n"
			"m=audio 10000 RTP/AVP 0\r\n"
			"a=rtpmap:0 PCMU/8000\r\n"
			"a=recvonly\r\n";
	}

	// One complete direct call: 200 (caller) INVITEs 206 (callee), 206
	// answers. Returns the Session the PBX holds afterwards. Mirrors
	// SessionTimer_test.cpp's runCallAnsweredWith(), minus the Session-Expires
	// plumbing this file has no use for.
	std::shared_ptr<Session> establishCall(RequestsHandler& handler, const std::string& callId)
	{
		const std::string callerIp = "192.168.50.10";
		const std::string calleeIp = "192.168.50.20";

		{
			std::string body = plainSdpBody(callerIp);
			std::string raw =
				"INVITE sip:206@server SIP/2.0\r\n"
				"Via: SIP/2.0/UDP " + callerIp + ":5060;branch=z9hG4bKi" + callId + "\r\n"
				"From: <sip:200@server>;tag=ctag" + callId + "\r\n"
				"To: <sip:206@server>\r\n"
				"Call-ID: " + callId + "\r\n"
				"CSeq: 1 INVITE\r\n"
				"Max-Forwards: 70\r\n"
				"Contact: <sip:200@" + callerIp + ":5060>\r\n"
				"Content-Type: application/sdp\r\n"
				"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
			handler.handle(RequestsHandler::getMessageFromPool(raw, addrFor(callerIp)));
		}
		{
			std::string body = plainSdpBody(calleeIp);
			std::string raw =
				"SIP/2.0 200 OK\r\n"
				"Via: SIP/2.0/UDP " + callerIp + ":5060;branch=z9hG4bKi" + callId + "\r\n"
				"From: <sip:200@server>;tag=ctag" + callId + "\r\n"
				"To: <sip:206@server>;tag=etag" + callId + "\r\n"
				"Call-ID: " + callId + "\r\n"
				"CSeq: 1 INVITE\r\n"
				"Contact: <sip:206@" + calleeIp + ":5060>\r\n"
				"Content-Type: application/sdp\r\n"
				"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
			handler.handle(RequestsHandler::getMessageFromPool(raw, addrFor(calleeIp)));
		}

		auto s = handler.getSession("Call-ID: " + callId);
		return s.has_value() ? s.value() : nullptr;
	}

	// An in-dialog request (re-INVITE or UPDATE) from the CALLER's leg,
	// carrying `body` as its SDP offer. `method` is "INVITE" or "UPDATE".
	std::shared_ptr<SipMessage> makeInDialogRequest(const std::string& method,
		const std::string& callId, int cseq, const std::string& body)
	{
		const std::string callerIp = "192.168.50.10";
		std::string raw =
			method + " sip:206@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + callerIp + ":5060;branch=z9hG4bKu" + callId + std::to_string(cseq) + "\r\n"
			"From: <sip:200@server>;tag=ctag" + callId + "\r\n"
			"To: <sip:206@server>;tag=etag" + callId + "\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: " + std::to_string(cseq) + " " + method + "\r\n"
			"Max-Forwards: 70\r\n"
			"Contact: <sip:200@" + callerIp + ":5060>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		return RequestsHandler::getMessageFromPool(raw, addrFor(callerIp));
	}
}

TEST(HoldDetection, OnReinviteDetectsLegacyZeroAddressHold)
{
	RequestsHandler handler(kServerIp, 5060,
		[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});
	handler.handle(makeRegister("200", "192.168.50.10", "reg-200"));
	handler.handle(makeRegister("206", "192.168.50.20", "reg-206"));

	auto session = establishCall(handler, "reinvite-legacy-hold");
	ASSERT_TRUE(session != nullptr);
	ASSERT_EQ(session->getState(), Session::State::Connected);

	handler.handle(makeInDialogRequest("INVITE", "reinvite-legacy-hold", 2,
		legacyHoldSdpBody("192.168.50.10")));

	EXPECT_EQ(session->getState(), Session::State::Held)
		<< "a=sendrecv at session level with the AUDIO section's own connection "
		   "blackholed (c=IN IP4 0.0.0.0) is the legacy RFC 2543 hold signal -- "
		   "getSdpDirection() alone (pre-#263) would read this as an active call";
}

TEST(HoldDetection, OnUpdateDetectsLegacyZeroAddressHold)
{
	RequestsHandler handler(kServerIp, 5060,
		[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});
	handler.handle(makeRegister("200", "192.168.50.10", "reg-200"));
	handler.handle(makeRegister("206", "192.168.50.20", "reg-206"));

	auto session = establishCall(handler, "update-legacy-hold");
	ASSERT_TRUE(session != nullptr);
	ASSERT_EQ(session->getState(), Session::State::Connected);

	handler.handle(makeInDialogRequest("UPDATE", "update-legacy-hold", 2,
		legacyHoldSdpBody("192.168.50.10")));

	EXPECT_EQ(session->getState(), Session::State::Held)
		<< "same legacy c=0.0.0.0 signal as the re-INVITE path, through UPDATE "
		   "(RFC 3311) instead";
}

// Pins decision 1 from the #263 design note: isHold() alone does not treat
// recvonly as hold (RFC 3264 s8.4 does not call it that), but this PBX always
// has at all three sites, and the fix must keep that explicitly rather than
// let it silently regress as a side effect of the isHold() swap.
TEST(HoldDetection, RecvOnlyOfferIsStillTreatedAsHold)
{
	RequestsHandler handler(kServerIp, 5060,
		[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});
	handler.handle(makeRegister("200", "192.168.50.10", "reg-200"));
	handler.handle(makeRegister("206", "192.168.50.20", "reg-206"));

	auto session = establishCall(handler, "reinvite-recvonly-hold");
	ASSERT_TRUE(session != nullptr);
	ASSERT_EQ(session->getState(), Session::State::Connected);

	handler.handle(makeInDialogRequest("INVITE", "reinvite-recvonly-hold", 2,
		recvonlySdpBody("192.168.50.10")));

	EXPECT_EQ(session->getState(), Session::State::Held)
		<< "recvonly must still count as hold -- isHold() alone would not, "
		   "since RFC 3264 s8.4 only names sendonly/inactive";
}

TEST(HoldDetection, ResumeAfterLegacyHoldReturnsToConnected)
{
	// The other half of the state machine: an ordinary sendrecv re-INVITE
	// after a legacy hold must clear it, the same as after a direction-based
	// one already did before this change.
	RequestsHandler handler(kServerIp, 5060,
		[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});
	handler.handle(makeRegister("200", "192.168.50.10", "reg-200"));
	handler.handle(makeRegister("206", "192.168.50.20", "reg-206"));

	auto session = establishCall(handler, "reinvite-legacy-resume");
	ASSERT_TRUE(session != nullptr);

	handler.handle(makeInDialogRequest("INVITE", "reinvite-legacy-resume", 2,
		legacyHoldSdpBody("192.168.50.10")));
	ASSERT_EQ(session->getState(), Session::State::Held) << "setup: the hold must take first";

	handler.handle(makeInDialogRequest("INVITE", "reinvite-legacy-resume", 3,
		plainSdpBody("192.168.50.10")));

	EXPECT_EQ(session->getState(), Session::State::Connected);
}

// Issue #281, found re-reading #263 for a self-audit: isHoldOffer()'s "first
// audio section, else session-level only" fallback used to initialize its
// section index to 0 rather than nMedia, so an offer with media sections but
// NO audio section silently read section 0 -- whatever type it actually was
// -- instead of falling back to session level. A direct SipSdpMessage unit
// test rather than a full handle() drive: the bug is entirely inside section
// selection, nothing about the surrounding call machinery matters to it.
TEST(HoldDetection, IsHoldOfferFallsBackToSessionLevelWhenNoAudioSectionExists)
{
	// Video-only offer: session level is plainly active (sendrecv, a real
	// connection address), but the ONE media section is video, marked
	// sendonly. Pre-#281, reading "section 0" unconditionally would read
	// THIS section and wrongly report hold; the fix must fall back to the
	// (non-holding) session level instead, since there is no audio section
	// to apply hold to at all.
	std::string body =
		"v=0\r\n"
		"o=- 0 0 IN IP4 192.168.50.10\r\n"
		"s=-\r\n"
		"c=IN IP4 192.168.50.10\r\n"
		"t=0 0\r\n"
		"a=sendrecv\r\n"
		"m=video 20000 RTP/AVP 96\r\n"
		"a=sendonly\r\n"
		"a=rtpmap:96 H264/90000\r\n";
	std::string raw =
		"INVITE sip:200@server SIP/2.0\r\n"
		"Via: SIP/2.0/UDP 192.168.50.10:5060;branch=z9hG4bK1\r\n"
		"From: <sip:100@server>;tag=a\r\n"
		"To: <sip:200@server>\r\n"
		"Call-ID: video-only\r\n"
		"CSeq: 1 INVITE\r\n"
		"Content-Type: application/sdp\r\n"
		"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;

	SipSdpMessage m(raw, addrFor("192.168.50.10"));
	EXPECT_FALSE(m.isHoldOffer())
		<< "no audio section exists, so this must fall back to the session "
		   "level's own sendrecv -- reading the video section's sendonly "
		   "instead is exactly issue #281";
}
