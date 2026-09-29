// SessionDisposition_test.cpp -- Issue #690, slice 1: Session carries a write-once
// Disposition (None/Busy/Unavailable/Cancel/Bye) next to State, and the four writers
// in RequestsHandler record it. State still carries the same four values and every
// reader still reads State, so nothing here changes what a call does; these tests
// pin only that the new field is filled by the right event and reset with the slot.
//
// Handler tests drive RequestsHandler::handle() end to end, the style
// CallForwardBusy_test.cpp uses. Each one asserts the disposition of the session
// its own Call-ID names, so the assertion proves the path it claims to drive.

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "RequestsHandler.hpp"
#include "Session.hpp"

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#else
#include <arpa/inet.h>
#endif

namespace
{
	sockaddr_in addrFor(const std::string& ip)
	{
		sockaddr_in s{};
		s.sin_family = AF_INET;
		s.sin_addr.s_addr = inet_addr(ip.c_str());
		s.sin_port = htons(5060);
		return s;
	}

	std::string sessionKey(const std::string& callId)
	{
		return "Call-ID: " + callId;
	}

	std::shared_ptr<SipMessage> makeRegister(const std::string& ext, const std::string& srcIp,
		const std::string& callId)
	{
		std::string raw =
			"REGISTER sip:server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + srcIp + ":5060;branch=z9hG4bKr" + callId + "\r\n"
			"From: <sip:" + ext + "@server>;tag=rt" + callId + "\r\n"
			"To: <sip:" + ext + "@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 REGISTER\r\n"
			"Contact: <sip:" + ext + "@" + srcIp + ":5060>;expires=3600\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addrFor(srcIp));
	}

	std::shared_ptr<SipMessage> makeInvite(const std::string& fromExt, const std::string& toExt,
		const std::string& srcIp, const std::string& callId, const std::string& branch)
	{
		std::string body =
			"v=0\r\n"
			"o=- 0 0 IN IP4 " + srcIp + "\r\n"
			"s=-\r\n"
			"c=IN IP4 " + srcIp + "\r\n"
			"t=0 0\r\n"
			"m=audio 10000 RTP/AVP 0\r\n"
			"a=rtpmap:0 PCMU/8000\r\n";
		std::string raw =
			"INVITE sip:" + toExt + "@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + srcIp + ":5060;branch=" + branch + "\r\n"
			"From: <sip:" + fromExt + "@server>;tag=ft" + callId + "\r\n"
			"To: <sip:" + toExt + "@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Max-Forwards: 70\r\n"
			"Contact: <sip:" + fromExt + "@" + srcIp + ":5060>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		return RequestsHandler::getMessageFromPool(raw, addrFor(srcIp));
	}

	// A final failure from the callee echoes the original INVITE's From/To
	// (RFC 3261), adding the callee's To-tag.
	std::shared_ptr<SipMessage> makeFailure(const std::string& status, const std::string& fromExt,
		const std::string& toExt, const std::string& calleeIp, const std::string& callId,
		const std::string& branch)
	{
		std::string raw =
			"SIP/2.0 " + status + "\r\n"
			"Via: SIP/2.0/UDP " + calleeIp + ":5060;branch=" + branch + "\r\n"
			"From: <sip:" + fromExt + "@server>;tag=ft" + callId + "\r\n"
			"To: <sip:" + toExt + "@server>;tag=bt" + callId + "\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addrFor(calleeIp));
	}

	std::shared_ptr<SipMessage> makeCancel(const std::string& fromExt, const std::string& toExt,
		const std::string& srcIp, const std::string& callId, const std::string& branch)
	{
		std::string raw =
			"CANCEL sip:" + toExt + "@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + srcIp + ":5060;branch=" + branch + "\r\n"
			"From: <sip:" + fromExt + "@server>;tag=ft" + callId + "\r\n"
			"To: <sip:" + toExt + "@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 CANCEL\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addrFor(srcIp));
	}

	std::shared_ptr<SipMessage> makeOk(const std::string& fromExt, const std::string& toExt,
		const std::string& calleeIp, const std::string& callId, const std::string& branch)
	{
		std::string body =
			"v=0\r\n"
			"o=- 0 0 IN IP4 " + calleeIp + "\r\n"
			"s=-\r\n"
			"c=IN IP4 " + calleeIp + "\r\n"
			"t=0 0\r\n"
			"m=audio 10002 RTP/AVP 0\r\n"
			"a=rtpmap:0 PCMU/8000\r\n";
		std::string raw =
			"SIP/2.0 200 OK\r\n"
			"Via: SIP/2.0/UDP " + calleeIp + ":5060;branch=" + branch + "\r\n"
			"From: <sip:" + fromExt + "@server>;tag=ft" + callId + "\r\n"
			"To: <sip:" + toExt + "@server>;tag=bt" + callId + "\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Contact: <sip:" + toExt + "@" + calleeIp + ":5060>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		return RequestsHandler::getMessageFromPool(raw, addrFor(calleeIp));
	}

	std::shared_ptr<SipMessage> makeBye(const std::string& fromExt, const std::string& toExt,
		const std::string& srcIp, const std::string& callId)
	{
		std::string raw =
			"BYE sip:" + toExt + "@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + srcIp + ":5060;branch=z9hG4bKbye" + callId + "\r\n"
			"From: <sip:" + fromExt + "@server>;tag=ft" + callId + "\r\n"
			"To: <sip:" + toExt + "@server>;tag=bt" + callId + "\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 2 BYE\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addrFor(srcIp));
	}

	// Two registered phones and an INVITE from the first to the second, still
	// ringing. The register-beep INVITEs the registrations fire are irrelevant:
	// every assertion below is keyed on this call's own Call-ID.
	struct Ringing
	{
		std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>> sent;
		RequestsHandler handler;
		std::string callerIp, calleeIp, callId, branch;

		Ringing(const std::string& base, const std::string& id)
			: handler(base + ".1", 5060,
				[this](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
					sent.emplace_back(addr, std::move(msg));
				}),
			  callerIp(base + ".21"), calleeIp(base + ".22"), callId(id), branch("z9hG4bK" + id)
		{
			handler.handle(makeRegister("601", callerIp, "reg-a-" + id));
			handler.handle(makeRegister("602", calleeIp, "reg-b-" + id));
			handler.handle(makeInvite("601", "602", callerIp, callId, branch));
		}

		Session::Disposition disposition()
		{
			auto s = handler.getSession(sessionKey(callId));
			EXPECT_TRUE(s.has_value()) << "the session for " << callId << " must still exist";
			return s.has_value() ? s.value()->getDisposition() : Session::Disposition::None;
		}
	};
}

// The field itself: starts empty, the first outcome sticks, None never overwrites,
// and a recycled pool slot (reset()) carries nothing over.
TEST(SessionDisposition, FirstWriteWinsAndResetClearsIt)
{
	Session s("Call-ID: unit-690", nullptr);
	EXPECT_EQ(s.getDisposition(), Session::Disposition::None);

	s.setDisposition(Session::Disposition::None);
	EXPECT_EQ(s.getDisposition(), Session::Disposition::None);

	s.setDisposition(Session::Disposition::Busy);
	s.setDisposition(Session::Disposition::Bye);
	s.setDisposition(Session::Disposition::None);
	EXPECT_EQ(s.getDisposition(), Session::Disposition::Busy)
		<< "a later write must not overwrite the recorded outcome";

	s.reset("Call-ID: unit-690b", nullptr);
	EXPECT_EQ(s.getDisposition(), Session::Disposition::None)
		<< "reset() recycles the slot: no outcome may survive it";
}

// Positive control: a ringing call has no outcome yet, so the assertions below
// cannot pass by the field defaulting to something else.
TEST(SessionDisposition, RingingCallHasNoDisposition)
{
	Ringing r("192.168.90", "disp-ring");
	EXPECT_EQ(r.disposition(), Session::Disposition::None);
}

TEST(SessionDisposition, BusyOnTheInitialInviteRecordsBusy)
{
	Ringing r("192.168.91", "disp-busy");
	r.handler.handle(makeFailure("486 Busy Here", "601", "602", r.calleeIp, r.callId, r.branch));
	EXPECT_EQ(r.disposition(), Session::Disposition::Busy);
}

TEST(SessionDisposition, UnavailableOnTheInitialInviteRecordsUnavailable)
{
	Ringing r("192.168.92", "disp-unavail");
	r.handler.handle(makeFailure("480 Temporarily Unavailable", "601", "602", r.calleeIp, r.callId, r.branch));
	EXPECT_EQ(r.disposition(), Session::Disposition::Unavailable);
}

TEST(SessionDisposition, CallerCancelRecordsCancel)
{
	Ringing r("192.168.93", "disp-cancel");
	r.handler.handle(makeCancel("601", "602", r.callerIp, r.callId, r.branch));
	EXPECT_EQ(r.disposition(), Session::Disposition::Cancel);
}

TEST(SessionDisposition, ByeOnAnAnsweredCallRecordsBye)
{
	Ringing r("192.168.94", "disp-bye");
	r.handler.handle(makeOk("601", "602", r.calleeIp, r.callId, r.branch));
	ASSERT_EQ(r.disposition(), Session::Disposition::None) << "answering is not an outcome";
	r.handler.handle(makeBye("601", "602", r.callerIp, r.callId));
	EXPECT_EQ(r.disposition(), Session::Disposition::Bye);
}
