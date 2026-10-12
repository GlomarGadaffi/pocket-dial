#pragma once

// Helpers shared by AdminPinOffthread_test.cpp and DtmfFactoryReset_test.cpp (#986 slice 3).
// A completed *PIN#code is now checked by a worker task and applied on a later tick,
// so a host test that wants the code's effect plays both, in that order.

#include <string>

#include "AdminPinVerify.hpp"
#include "RequestsHandler.hpp"
#include "SipMessage.hpp"

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#else
#include <arpa/inet.h>
#endif

namespace adminpin_test
{
	// A live call from `ext` at `ip`: an INVITE to the 777 echo test, which the PBX answers
	// itself, so the session exists afterwards under "Call-ID: <callId>". The admin's DTMF
	// digits ride on it, as they do on a real handset, and a test hangs up with
	// forceDisconnect(ext). Does nothing when the call is already up.
	inline void startEchoCall(RequestsHandler& h, const std::string& ext, const std::string& ip,
		const std::string& callId)
	{
		if (h.getSession("Call-ID: " + callId).has_value()) return;
		sockaddr_in s{};
		s.sin_family = AF_INET;
		s.sin_addr.s_addr = inet_addr(ip.c_str());
		s.sin_port = htons(5060);
		const std::string body =
			"v=0\r\no=- 0 0 IN IP4 " + ip + "\r\ns=-\r\nc=IN IP4 " + ip + "\r\nt=0 0\r\n"
			"m=audio 10000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n";
		h.handle(RequestsHandler::getMessageFromPool(
			"INVITE sip:777@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + ip + ":5060;branch=z9hG4bKe" + callId + "\r\n"
			"From: <sip:" + ext + "@server>;tag=et" + callId + "\r\n"
			"To: <sip:777@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Max-Forwards: 70\r\n"
			"Contact: <sip:" + ext + "@" + ip + ":5060>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body, s));
	}

	// The worker task's pass(es), then the tick task's: the order the board runs them in.
	inline void settle(RequestsHandler& h)
	{
		while (adminpin::workForTest()) {}
		h.forceNextTickForTest();
		h.tick();
	}
}
