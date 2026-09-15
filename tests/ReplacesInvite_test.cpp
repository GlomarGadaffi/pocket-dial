// ReplacesInvite_test.cpp — Issue #229 regression pin.
//
// #199's RFC compliance map named `Supported: replaces` as though the header
// alone gated "BLF-key call pickup". It doesn't: RFC 3891 §3's actual
// mechanism for that is a UA sending an INVITE that ITSELF carries a
// `Replaces` header, naming an existing dialog by Call-ID plus both tags,
// which the far end is supposed to answer in place of ringing the target
// fresh (and BYE the named dialog out once the replacement succeeds). That
// path has no handler anywhere in src/ -- onInvite() takes no Replaces
// branch at all -- so a phone attempting a BLF-key pickup or a phone-native
// "grab this call" today just places an ordinary second call.
//
// What #200/#226 advertise "replaces" in Supported FOR is real: onRefer()'s
// REFER ?Replaces= attended-transfer splice (issue #131,
// AttendedTransfer_test.cpp). That's a different RFC 3891 mechanism, reached
// a different way, and honestly claimed. See the comment above
// kSupportedOptionTags in RequestsHandler.cpp for the full scope call.
//
// #229 chose -- deliberately, for now -- to document this gap rather than
// build full INVITE-with-Replaces handling (which would also need whole-
// dialog Call-ID+both-tags matching and early-only handling to be RFC-correct,
// not just a header read). This test is the trip-wire for that decision: it
// pins that a Replaces header on an INVITE is CURRENTLY a complete no-op. A
// real implementation landing later must edit this test deliberately, not
// leave it accidentally passing for the wrong reason.

#include <gtest/gtest.h>

#include <string>
#include <utility>
#include <vector>

#include "RequestsHandler.hpp"
#include "SipMessage.hpp"

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#else
#include <arpa/inet.h>
#endif

namespace
{
	sockaddr_in addrFor(const std::string& ip)
	{
		sockaddr_in a{};
		a.sin_family = AF_INET;
		a.sin_addr.s_addr = inet_addr(ip.c_str());
		a.sin_port = htons(5060);
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

	std::string sdpBody(const std::string& ip, int port)
	{
		return
			"v=0\r\n"
			"o=- 0 0 IN IP4 " + ip + "\r\n"
			"s=-\r\n"
			"c=IN IP4 " + ip + "\r\n"
			"t=0 0\r\n"
			"m=audio " + std::to_string(port) + " RTP/AVP 0\r\n"
			"a=rtpmap:0 PCMU/8000\r\n";
	}

	// SipMessage::getCallID() (and therefore the _sessions map key) is the FULL
	// "Call-ID: <value>" header line, not the bare value used to build the raw
	// messages below -- see CallPickup_test.cpp's identical helper.
	std::string sessionKey(const std::string& callId)
	{
		return "Call-ID: " + callId;
	}

	using Outbox = std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>>;

	std::string findSentTo(const Outbox& sent, const sockaddr_in& addr, const std::string& needle)
	{
		for (auto it = sent.rbegin(); it != sent.rend(); ++it)
		{
			if (it->first.sin_addr.s_addr != addr.sin_addr.s_addr) continue;
			if (it->first.sin_port != addr.sin_port) continue;
			if (!it->second) continue;
			std::string raw = it->second->toString();
			if (raw.find(needle) != std::string::npos) return raw;
		}
		return {};
	}

	bool anySentTo(const Outbox& sent, const sockaddr_in& addr, const std::string& needle)
	{
		return !findSentTo(sent, addr, needle).empty();
	}
}

TEST(ReplacesInvite, AReplacesHeaderOnAnInviteDoesNotTouchTheNamedDialogAtAll)
{
	// A and B are an established call -- the dialog a BLF-key pickup or a
	// phone-native "grab this call" would name via Replaces. C sends the
	// Replaces INVITE to a FOURTH extension D (rather than to B directly) so
	// the assertions below can't be confused by D/B already being busy on
	// something else -- the point under test is purely whether the header
	// does anything, not how a busy target would be handled if it did.
	Outbox sent;
	RequestsHandler handler("192.168.50.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	const sockaddr_in aAddr = addrFor("192.168.50.10");
	const sockaddr_in bAddr = addrFor("192.168.50.20");
	const sockaddr_in cAddr = addrFor("192.168.50.30");
	const sockaddr_in dAddr = addrFor("192.168.50.40");

	handler.handle(makeRegister("500", "192.168.50.10", "reg-500"));
	handler.handle(makeRegister("501", "192.168.50.20", "reg-501"));
	handler.handle(makeRegister("502", "192.168.50.30", "reg-502"));
	handler.handle(makeRegister("503", "192.168.50.40", "reg-503"));

	// A calls B, B answers -- the established dialog Replaces will name.
	const std::string abCallId = "ab-established";
	{
		const std::string body = sdpBody("192.168.50.10", 10000);
		const std::string raw =
			"INVITE sip:501@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP 192.168.50.10:5060;branch=z9hG4bKab\r\n"
			"From: <sip:500@server>;tag=atag\r\n"
			"To: <sip:501@server>\r\n"
			"Call-ID: " + abCallId + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Max-Forwards: 70\r\n"
			"Contact: <sip:500@192.168.50.10:5060>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		handler.handle(RequestsHandler::getMessageFromPool(raw, aAddr));
	}
	{
		const std::string body = sdpBody("192.168.50.20", 20000);
		const std::string raw =
			"SIP/2.0 200 OK\r\n"
			"Via: SIP/2.0/UDP 192.168.50.10:5060;branch=z9hG4bKab\r\n"
			"From: <sip:500@server>;tag=atag\r\n"
			"To: <sip:501@server>;tag=btag\r\n"
			"Call-ID: " + abCallId + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Contact: <sip:501@192.168.50.20:5060>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		handler.handle(RequestsHandler::getMessageFromPool(raw, bAddr));
	}

	auto abBefore = handler.getSession(sessionKey(abCallId));
	ASSERT_TRUE(abBefore.has_value());
	ASSERT_EQ(abBefore.value()->getState(), Session::State::Connected);

	sent.clear(); // only the Replaces INVITE's own traffic matters from here

	// C sends the Replaces INVITE to D. to-tag/from-tag match the A-B dialog
	// exactly as a conformant phone would build them from the dialog info it
	// learned (e.g. an RFC 4235 NOTIFY off the BLF subscription).
	const std::string pickupCallId = "pickup-attempt";
	{
		const std::string body = sdpBody("192.168.50.30", 30000);
		const std::string raw =
			"INVITE sip:503@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP 192.168.50.30:5060;branch=z9hG4bKpu\r\n"
			"From: <sip:502@server>;tag=ctag\r\n"
			"To: <sip:503@server>\r\n"
			"Call-ID: " + pickupCallId + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Max-Forwards: 70\r\n"
			"Contact: <sip:502@192.168.50.30:5060>\r\n"
			"Replaces: " + abCallId + ";to-tag=btag;from-tag=atag\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		handler.handle(RequestsHandler::getMessageFromPool(raw, cAddr));
	}

	// THE GAP: no BYE, re-INVITE or any other traffic ever reaches the named
	// dialog's two parties because of the Replaces header. If any of these
	// ever fire, #229's INVITE-with-Replaces path has been implemented and
	// this whole test needs rewriting to match the new, real behaviour.
	EXPECT_FALSE(anySentTo(sent, aAddr, "BYE sip:"))
		<< "an unimplemented Replaces header must not tear down the dialog it named";
	EXPECT_FALSE(anySentTo(sent, bAddr, "BYE sip:"))
		<< "an unimplemented Replaces header must not tear down the dialog it named";
	EXPECT_FALSE(anySentTo(sent, bAddr, "INVITE sip:"))
		<< "no re-INVITE reached B either -- nothing about B's leg moved at all";

	auto abAfter = handler.getSession(sessionKey(abCallId));
	ASSERT_TRUE(abAfter.has_value());
	EXPECT_EQ(abAfter.value()->getState(), Session::State::Connected)
		<< "the named dialog must be completely unaffected by an INVITE it was never told about";
	ASSERT_NE(abAfter.value()->getDest(), nullptr);
	EXPECT_EQ(abAfter.value()->getDest()->getNumber(), "501")
		<< "B is still A's dest -- the Replaces header substituted nobody";

	// THE DOCUMENTED BEHAVIOUR: C's INVITE was instead dispatched as an
	// entirely ordinary new call to D, exactly as if the Replaces header had
	// never been on the wire -- because nothing reads it.
	const std::string forkToD = findSentTo(sent, dAddr, "INVITE sip:503@");
	ASSERT_FALSE(forkToD.empty())
		<< "the Replaces INVITE should still ring its own Request-URI target "
		   "like a plain call";

	auto pickupSession = handler.getSession(sessionKey(pickupCallId));
	ASSERT_TRUE(pickupSession.has_value());
	EXPECT_EQ(pickupSession.value()->getState(), Session::State::Invited)
		<< "a brand-new session ringing D, not a splice onto the named A-B dialog";
}
