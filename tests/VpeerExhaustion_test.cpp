// VpeerExhaustion_test.cpp — issue #412: every allocateVirtualPeer() caller must
// survive an exhausted pool.
//
// allocateVirtualPeer() returns nullptr once the pool AND the #101A heap
// fallback behind it are spent (and, after #409, as soon as the pool is). Six
// call sites used the result unchecked -- setDest(nullptr), or a null caller
// handed to allocateSession() -- and code downstream dereferences getDest()
// without a check. These tests drive each path end to end through handle()
// with capacity exhausted and pin three things:
//
//   1. the caller is refused with exactly ONE 503 (a count, not "some 503");
//   2. nothing the path had already claimed is left behind -- no session is
//      published, no conference leg / anchor bridge stays attached;
//   3. the same dial SUCCEEDS once capacity returns, so the refusal is the
//      pool's doing and not a broken setup that would fail anyway.
//
// This file covers the conference (888) join. VpeerExhaustion_vm_anchor_test.cpp
// covers voicemail deposit and retrieval and the synchronous anchor (555) dial.
//
// NOT covered by any host test, stated so nobody reads the file list as full
// coverage: the ASYNC anchor branch of originateAnchorCall() and
// routeInboundAnchorCall() (inbound PSTN). Both run only with a non-Loopback
// anchor client, and on host TelephonyAnchorClient is a stub whose
// isConnected() is always false and whose event callback is discarded, so
// neither branch is reachable through handle(). Their guards are verified by
// reading; reaching them needs a host-only seam that does not exist yet.
//
// exhaustVirtualPeersForTest() draws through the real allocator until it
// refuses, so it exhausts whatever sits behind the pool too. Hold its result
// for as long as the pool should stay empty.

#include <gtest/gtest.h>

#include <string>
#include <utility>
#include <vector>

#include "ConferenceRoom.hpp"
#include "RequestsHandler.hpp"

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#else
#include <arpa/inet.h>
#endif

namespace
{
	using Sent = std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>>;

	sockaddr_in addrFor(const std::string& ip)
	{
		sockaddr_in s{};
		s.sin_family = AF_INET;
		s.sin_addr.s_addr = inet_addr(ip.c_str());
		s.sin_port = htons(5060);
		return s;
	}

	std::shared_ptr<SipMessage> makeRegister(const std::string& ext, const std::string& srcIp,
		const std::string& callId)
	{
		const std::string raw =
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
		const std::string& srcIp, const std::string& callId)
	{
		const std::string body =
			"v=0\r\n"
			"o=- 0 0 IN IP4 " + srcIp + "\r\n"
			"s=-\r\n"
			"c=IN IP4 " + srcIp + "\r\n"
			"t=0 0\r\n"
			"m=audio 10000 RTP/AVP 0\r\n"
			"a=rtpmap:0 PCMU/8000\r\n";
		const std::string raw =
			"INVITE sip:" + toExt + "@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + srcIp + ":5060;branch=z9hG4bKi" + callId + "\r\n"
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

	// Responses sent TO `ip` whose start line contains `status`.
	size_t countTo(const Sent& sent, const std::string& ip, const std::string& status)
	{
		const uint32_t want = inet_addr(ip.c_str());
		size_t n = 0;
		for (const auto& [addr, msg] : sent)
		{
			if (!msg || addr.sin_addr.s_addr != want) continue;
			const std::string raw = msg->toString();
			if (raw.substr(0, raw.find("\r\n")).find(status) != std::string::npos) ++n;
		}
		return n;
	}
}

TEST(VpeerExhaustion, ConferenceJoinIsRefused503AndLeavesTheRoom)
{
	Sent sent;
	RequestsHandler handler("192.168.7.1", 5060,
		[&sent](const sockaddr_in& a, std::shared_ptr<SipMessage> m) { sent.emplace_back(a, std::move(m)); });
	const std::string ext(ConferenceRoom::EXT);
	const std::string ip = "192.168.7.51";
	handler.handle(makeRegister("501", ip, "reg-501"));

	{
		auto held = handler.exhaustVirtualPeersForTest();
		ASSERT_FALSE(held.empty()) << "nothing was drawn -- the pool was never exhausted";
		sent.clear();

		handler.handle(makeInvite("501", ext, ip, "vx-conf"));

		EXPECT_EQ(countTo(sent, ip, "503"), 1u) << "refused exactly once";
		EXPECT_EQ(countTo(sent, ip, "200 OK"), 0u) << "never a 200 for a leg with no peer";
		EXPECT_FALSE(handler.getSession("Call-ID: vx-conf").has_value())
			<< "a refused join must not publish a session";
		EXPECT_EQ(handler.getConferenceLegs(), 0)
			<< "the leg joined before the peer was drawn must be left again";
	}

	// Capacity back: the same dial is admitted, so the refusal above was the pool.
	sent.clear();
	handler.handle(makeInvite("501", ext, ip, "vx-conf-2"));
	EXPECT_EQ(countTo(sent, ip, "200 OK"), 1u);
	EXPECT_TRUE(handler.getSession("Call-ID: vx-conf-2").has_value());
	EXPECT_EQ(handler.getConferenceLegs(), 1);
}

