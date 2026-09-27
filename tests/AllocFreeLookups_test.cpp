// Issue #464 (#284 batch C): the per-request lookups must not allocate.
//
// Three sites built a temporary on every packet:
//   - RequestsHandler::getSession(string_view) keyed an unordered_map, so every
//     lookup built a std::string of the full "Call-ID: ..." line (always past
//     SSO) -- up to three times per request via noteDialogCSeq();
//   - PbxEnv::forEachSessionInvolving took `const std::function&`, and the BLF
//     visitor captures 16 B, past std::function's 8 B inline buffer on Xtensa
//     (and libstdc++'s 16 B on 64-bit hosts is not the bound that matters);
//   - SipTrunk's find* normalised the Call-ID into a std::string on every
//     response and BYE, trunk dialogs or not.
// Each test counts operator-new calls on this thread (AllocGuard) around one
// such lookup after everything it needs already exists.

#include <gtest/gtest.h>

#include <string>
#include <string_view>

#include "FakePbxEnv.hpp"
#include "RequestsHandler.hpp"
#include "SipHeaderUtil.hpp"
#include "SipTrunk.hpp"
#include "support/AllocCounter.hpp"

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#else
#include <arpa/inet.h>
#endif

namespace
{
	sockaddr_in addrFor(const std::string& ip, uint16_t port = 5060)
	{
		sockaddr_in a{};
		a.sin_family = AF_INET;
		a.sin_addr.s_addr = inet_addr(ip.c_str());
		a.sin_port = htons(port);
		return a;
	}

	std::shared_ptr<SipMessage> makeRegister(const std::string& ext, const std::string& ip)
	{
		std::string raw =
			"REGISTER sip:server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + ip + ":5060;branch=z9hG4bKr464" + ext + "\r\n"
			"From: <sip:" + ext + "@server>;tag=rt" + ext + "\r\n"
			"To: <sip:" + ext + "@server>\r\n"
			"Call-ID: reg-464-" + ext + "\r\n"
			"CSeq: 1 REGISTER\r\n"
			"Contact: <sip:" + ext + "@" + ip + ":5060>;expires=3600\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addrFor(ip));
	}
}

// The #464 "done when": a lookup of an existing session by the Call-ID line a
// request carries allocates nothing.
TEST(AllocFreeLookups, SessionLookupByCallIdLineAllocatesNothing)
{
	RequestsHandler handler("192.168.46.1", 5060,
		[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});
	handler.handle(makeRegister("100", "192.168.46.10"));
	handler.handle(makeRegister("106", "192.168.46.20"));

	const std::string callId = "alloc-free-lookup-464-0123456789@192.168.46.10";
	{
		const std::string sdp = "v=0\r\no=- 0 0 IN IP4 192.168.46.10\r\ns=-\r\nc=IN IP4 192.168.46.10\r\n"
		                        "t=0 0\r\nm=audio 10000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n";
		std::string inv =
			"INVITE sip:106@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP 192.168.46.10:5060;branch=z9hG4bKi464\r\n"
			"From: <sip:100@server>;tag=a464\r\n"
			"To: <sip:106@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Max-Forwards: 70\r\n"
			"Contact: <sip:100@192.168.46.10:5060>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(sdp.size()) + "\r\n\r\n" + sdp;
		handler.handle(RequestsHandler::getMessageFromPool(inv, addrFor("192.168.46.10")));
	}
	// The key form every handler uses: the whole header line, as
	// SipMessage::getCallID() returns it.
	const std::string line = "Call-ID: " + callId;
	ASSERT_TRUE(handler.getSession(line).has_value()) << "the INVITE must have created the session";

	const std::string_view view(line);
	AllocGuard guard;
	const bool found = handler.getSession(view).has_value();
	const bool missing = handler.getSession(std::string_view("Call-ID: no-such-call-464@nowhere")).has_value();
	const size_t allocs = guard.delta();

	EXPECT_TRUE(found);
	EXPECT_FALSE(missing);
	EXPECT_EQ(allocs, 0u) << "getSession(string_view) must not build a temporary std::string key";
}

// A visitor capturing four references (16 B) -- the BLF computeDialogState
// shape -- passes through forEachSessionInvolving without a heap allocation.
TEST(AllocFreeLookups, SessionVisitorWithAWideCaptureAllocatesNothing)
{
	FakePbxEnv env;
	const sockaddr_in phone = FakePbxEnv::addr("192.168.1.50", 5060);
	auto caller = std::make_shared<SipClient>("101", phone);
	auto callee = std::make_shared<SipClient>("102", FakePbxEnv::addr("192.168.1.51", 5060));
	auto session = std::make_shared<Session>("call-464", caller);
	session->setDest(callee);
	env.sessions.emplace("call-464", session);

	int visits = 0, callerRoles = 0, calleeRoles = 0;
	const Session* seen = nullptr;

	AllocGuard guard;
	env.forEachSessionInvolving("101",
		[&visits, &callerRoles, &calleeRoles, &seen](const std::string&, const Session& s,
			PbxEnv::DialogRole role)
	{
		++visits;
		(role == PbxEnv::DialogRole::Caller ? callerRoles : calleeRoles)++;
		seen = &s;
	});
	const size_t allocs = guard.delta();

	EXPECT_EQ(visits, 1);
	EXPECT_EQ(callerRoles, 1);
	EXPECT_EQ(calleeRoles, 0);
	EXPECT_EQ(seen, session.get());
	EXPECT_EQ(allocs, 0u) << "a 16 B capture must not heap-allocate through the visitor parameter";
}

// SipTrunk sees every SIP response and BYE the engine handles (it is asked
// first), almost always with no trunk dialog at all. That miss must be free.
TEST(AllocFreeLookups, TrunkLookupMissOnAResponseOrByeAllocatesNothing)
{
	FakePbxEnv env;
	SipTrunk trunk(env);
	const sockaddr_in from = FakePbxEnv::addr("192.168.1.70", 5060);
	auto ok = std::make_shared<SipMessage>(std::string(
		"SIP/2.0 200 OK\r\n"
		"Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bKnotours464\r\n"
		"From: <sip:100@server>;tag=a\r\n"
		"To: <sip:106@server>;tag=b\r\n"
		"Call-ID: not-a-trunk-call-464-0123456789@192.168.1.70\r\n"
		"CSeq: 1 INVITE\r\n"
		"Content-Length: 0\r\n\r\n"), from);
	auto bye = std::make_shared<SipMessage>(std::string(
		"BYE sip:100@server SIP/2.0\r\n"
		"Via: SIP/2.0/UDP 192.168.1.70:5060;branch=z9hG4bKbye464\r\n"
		"From: <sip:106@server>;tag=b\r\n"
		"To: <sip:100@server>;tag=a\r\n"
		"Call-ID: not-a-trunk-call-464-0123456789@192.168.1.70\r\n"
		"CSeq: 2 BYE\r\n"
		"Content-Length: 0\r\n\r\n"), from);

	AllocGuard guard;
	const bool claimedOk  = trunk.handleResponse(ok);
	const bool claimedBye = trunk.handleBye(bye);
	const size_t allocs = guard.delta();

	EXPECT_FALSE(claimedOk);
	EXPECT_FALSE(claimedBye);
	EXPECT_EQ(allocs, 0u) << "a trunk-dialog miss must not normalise the Call-ID into a std::string";
}

// The view twin must agree with stripHeaderName() everywhere it is used.
TEST(AllocFreeLookups, StripHeaderNameViewMatchesTheCopyingForm)
{
	const char* cases[] = {
		"Call-ID: abc@host", "Call-ID:abc@host", "Call-ID: \tabc@host\r\n", "abc@host",
		"<sip:100@host>", "i: compact@host", "", ":", "X-Weird_Name: v", "Call-ID: ",
	};
	for (const char* c : cases)
	{
		EXPECT_EQ(std::string(siphdr::stripHeaderNameView(c)), siphdr::stripHeaderName(c)) << "[" << c << "]";
	}
	AllocGuard guard;
	const auto v = siphdr::stripHeaderNameView("Call-ID: a-long-call-id-464-0123456789@host");
	EXPECT_EQ(guard.delta(), 0u);
	EXPECT_EQ(v, "a-long-call-id-464-0123456789@host");
}
