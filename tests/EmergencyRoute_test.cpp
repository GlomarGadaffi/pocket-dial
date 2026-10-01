// EmergencyRoute_test.cpp — issue #521: an emergency number is delivered by a
// provider that places REAL calls, or refused with 503. Never simulated.
//
// Before #521, routeEmergencyCall() handed 911 to whatever anchor booted. On a
// board with no Telephony-API provider that is the loopback simulator, which
// answers every call it is handed: the caller heard a connected call to
// nothing, and the front desk was told the 911 call had been ROUTED. A
// configured SIP trunk was never consulted at all. Section A below pins the
// defect with nothing but APIs that already existed, so it runs red against
// the unfixed engine; section B pins the parts #521 added (the route report,
// the boot warning, /api/status, the dashboard banner).
//
// NO TEST HERE MAY DIAL AN EMERGENCY NUMBER OVER ANY NETWORK. Every carrier
// INVITE goes to the handler's send callback, which only captures it; the SBC
// is 203.0.113.5 (RFC 5737 TEST-NET-3, not routable) and no test sends to it.
// The one real socket, section B's HttpServer, is bound to 127.0.0.1.
//
// Ports: this file owns 18290-18299. See CONTRIBUTING_FIRMWARE.md's table.

#include <gtest/gtest.h>

#include <chrono>
#include <cstdio>
#include <memory>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include "AdminAuth.hpp"
#include "HttpServer.hpp"
#include "LoopbackAnchorClient.hpp"
#include "RequestsHandler.hpp"
#include "TrunkConfigStore.hpp"
#include "index_html.h"

namespace
{
	constexpr const char* kServerIp  = "192.168.79.1";
	constexpr const char* kHandsetIp = "192.168.79.11";
	constexpr const char* kSbcIp     = "203.0.113.5";   // RFC 5737 TEST-NET-3

	sockaddr_in addrFor(const std::string& ip, uint16_t port = 5060)
	{
		sockaddr_in s{};
		s.sin_family = AF_INET;
		s.sin_addr.s_addr = inet_addr(ip.c_str());
		s.sin_port = htons(port);
		return s;
	}

	SipTrunk::Config trunkConfig()
	{
		SipTrunk::Config c;
		std::snprintf(c.host, sizeof(c.host), "%s", kSbcIp);
		c.port = 5060;
		std::snprintf(c.fromUser, sizeof(c.fromUser), "%s", "15551230000");
		c.enabled = true;
		return c;
	}

	std::shared_ptr<SipMessage> makeRegister(const std::string& ext,
		const std::string& ip = kHandsetIp)
	{
		const std::string raw =
			"REGISTER sip:server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + ip + ":5060;branch=z9hG4bKer" + ext + "\r\n"
			"From: <sip:" + ext + "@server>;tag=er" + ext + "\r\n"
			"To: <sip:" + ext + "@server>\r\n"
			"Call-ID: er-reg-" + ext + "\r\n"
			"CSeq: 1 REGISTER\r\n"
			"Contact: <sip:" + ext + "@" + ip + ":5060>;expires=3600\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addrFor(ip));
	}

	// `payloadType` 0 is PCMU, which every route accepts; 8 alone is the
	// PCMA-only offer the anchor's codec gate rejects (issue #314).
	std::shared_ptr<SipMessage> makeInvite(const std::string& dialed, const std::string& callId,
		int payloadType = 0, const std::string& ext = "101", const std::string& ip = kHandsetIp)
	{
		const std::string rtpmap = payloadType == 8 ? "a=rtpmap:8 PCMA/8000\r\n"
		                                            : "a=rtpmap:0 PCMU/8000\r\n";
		const std::string body =
			"v=0\r\n"
			"o=- 0 0 IN IP4 " + ip + "\r\n"
			"s=-\r\n"
			"c=IN IP4 " + ip + "\r\n"
			"t=0 0\r\n"
			"m=audio 40000 RTP/AVP " + std::to_string(payloadType) + "\r\n" + rtpmap;
		const std::string raw =
			"INVITE sip:" + dialed + "@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + ip + ":5060;branch=z9hG4bKei" + callId + "\r\n"
			"From: <sip:" + ext + "@server>;tag=ef" + callId + "\r\n"
			"To: <sip:" + dialed + "@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Max-Forwards: 70\r\n"
			"Contact: <sip:" + ext + "@" + ip + ":5060>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		return RequestsHandler::getMessageFromPool(raw, addrFor(ip));
	}

	// Ext 101 registered, every outbound message captured with its address.
	// Boots exactly as every host handler does: the loopback anchor, no trunk.
	struct Bench
	{
		std::vector<std::pair<sockaddr_in, std::string>> sent;
		std::unique_ptr<RequestsHandler> handler;

		Bench()
		{
			handler = std::make_unique<RequestsHandler>(kServerIp, 5060,
				[this](const sockaddr_in& a, std::shared_ptr<SipMessage> m) {
					sent.emplace_back(a, m->toString());
				});
			handler->handle(makeRegister("101"));
			sent.clear();
		}

		LoopbackAnchorClient* loopback()
		{
			return dynamic_cast<LoopbackAnchorClient*>(handler->anchorClientForTest());
		}

		// Messages whose FIRST LINE contains `needle`, optionally only those
		// addressed to `ip`.
		size_t count(const std::string& needle, const char* ip = nullptr) const
		{
			size_t n = 0;
			for (const auto& [addr, raw] : sent)
			{
				if (ip && addr.sin_addr.s_addr != inet_addr(ip)) continue;
				if (raw.substr(0, raw.find("\r\n")).find(needle) != std::string::npos) ++n;
			}
			return n;
		}

		bool saw(const std::string& needle) const
		{
			for (const auto& p : sent)
			{
				if (p.second.find(needle) != std::string::npos) return true;
			}
			return false;
		}

		std::string dump() const
		{
			std::string out;
			for (const auto& p : sent) out += p.second.substr(0, p.second.find("\r\n")) + "\n";
			return out;
		}
	};
}

// ═════════════════════════════════════════════════════════════════════════════
// A. The defect. Existing APIs only, so these run red against the unfixed engine.
// ═════════════════════════════════════════════════════════════════════════════

TEST(EmergencyRoute, ALoopbackOnlyBoardRefusesEveryEmergencyNumberAndAnswersNone)
{
	for (const char* dialed : {"911", "9911", "933", "9933"})
	{
		SCOPED_TRACE(dialed);
		Bench b;
		ASSERT_NE(b.loopback(), nullptr) << "host build should boot the loopback anchor";
		ASSERT_TRUE(b.loopback()->isConnected())
			<< "the simulator must be UP, or this passes for the wrong reason";
		const std::string callId = std::string("er-loop-") + dialed;

		b.handler->handle(makeInvite(dialed, callId));

		EXPECT_EQ(b.count("SIP/2.0 503 Emergency Call Not Routable"), 1u)
			<< "no real route: refuse, exactly once. Got:\n" << b.dump();
		EXPECT_EQ(b.count("SIP/2.0 200"), 0u)
			<< "THE defect: the loopback simulator answered an emergency call:\n" << b.dump();
		EXPECT_EQ(b.count("SIP/2.0 180"), 0u)
			<< "not even ringback -- nothing is being rung:\n" << b.dump();
		EXPECT_EQ(b.loopback()->lastMakeCallDestination(), "")
			<< "the simulator must never be asked to dial an emergency number";
		EXPECT_EQ(b.handler->anchorBridgeForCallIdForTest("Call-ID: " + callId), nullptr)
			<< "and no media bridge may be attached to a call that does not exist";
	}
}

TEST(EmergencyRoute, TheRefusalSaysThatNoRouteIsConfigured)
{
	Bench b;

	b.handler->handle(makeInvite("911", "er-loop-warn"));

	// A distinct reason from "no outbound trunk connected" (a real provider
	// that is down right now), so an operator can tell a board that was never
	// set up from one that has lost its carrier.
	EXPECT_TRUE(b.saw("Emergency call could not be routed: no emergency route configured"))
		<< b.dump();
	EXPECT_FALSE(b.saw("Retry-After"))
		<< "a 911 refusal must never tell the handset to back off";
}

TEST(EmergencyRoute, WithATrunkConfiguredTheCallGoesToTheCarrierAndNotTheLoopback)
{
	Bench b;
	b.handler->setTrunkConfig(trunkConfig());

	b.handler->handle(makeInvite("911", "er-trunk-911"));

	EXPECT_EQ(b.count("INVITE sip:911@" + std::string(kSbcIp), kSbcIp), 1u)
		<< "the carrier must be sent exactly one INVITE for the bare 911:\n" << b.dump();
	EXPECT_EQ(b.count("INVITE sip:+911"), 0u)
		<< "\"+911\" is country code 91, not an emergency number";
	EXPECT_EQ(b.count("SIP/2.0 180", kHandsetIp), 1u)
		<< "the caller is told the call is progressing:\n" << b.dump();
	EXPECT_EQ(b.count("SIP/2.0 503"), 0u) << b.dump();
	EXPECT_EQ(b.loopback()->lastMakeCallDestination(), "")
		<< "the simulator must not see the call even when a trunk carries it";
	EXPECT_EQ(b.handler->trunkRelaysInUseForTest(), 1u)
		<< "the relay pair that will carry the caller's audio is held";
}

TEST(EmergencyRoute, TheTrunkIsHandedTheBareNumberWhateverWasDialed)
{
	for (const auto& [dialed, bare] : std::vector<std::pair<std::string, std::string>>{
		{"9911", "911"}, {"933", "933"}, {"9933", "933"}})
	{
		SCOPED_TRACE(dialed);
		Bench b;
		b.handler->setTrunkConfig(trunkConfig());

		b.handler->handle(makeInvite(dialed, "er-trunk-" + dialed));

		EXPECT_EQ(b.count("INVITE sip:" + bare + "@" + std::string(kSbcIp), kSbcIp), 1u)
			<< b.dump();
		EXPECT_EQ(b.count("INVITE sip:" + dialed + "@"), dialed == bare ? 1u : 0u)
			<< "the prefixed form must never reach the carrier";
	}
}

TEST(EmergencyRoute, ADialRuleCannotHandTheLoopbackAnEmergencyNumber)
{
	// routeEmergencyCall() never offers the simulator an emergency number, but
	// a dial-plan Trunk rule's transform can MAKE one, and with no trunk that
	// rule lands on the anchor. The guard below routeEmergencyCall() catches it.
	{
		// Positive control: the rule is accepted and does reach the simulator,
		// or the refusal below would pass for want of a matching rule.
		Bench b;
		b.handler->setDialRule("0", "trunk", "5551234", 1);
		b.handler->handle(makeInvite("0", "er-rule-control"));
		ASSERT_EQ(b.loopback()->lastMakeCallDestination(), "5551234") << b.dump();
	}

	Bench b;
	b.handler->setDialRule("0", "trunk", "911", 1);

	b.handler->handle(makeInvite("0", "er-rule-911"));

	EXPECT_EQ(b.loopback()->lastMakeCallDestination(), "")
		<< "a rule rewriting 0 to 911 must not get a simulated answer";
	EXPECT_EQ(b.count("SIP/2.0 503 Emergency Call Not Routable"), 1u) << b.dump();
	EXPECT_EQ(b.count("SIP/2.0 200"), 0u) << b.dump();
}

TEST(EmergencyRoute, ADialRuleThatProducesAnEmergencyNumberTakesTheEmergencyPath)
{
	// #538 review M2: pstnUri() sends 911 bare, so on a trunk board a rule
	// rewriting 0 to 911 places a REAL 911. It must be the emergency path's 911:
	// logged, and the front desk notified. Before the fix it was a plain trunk
	// call with no notification at all.
	Bench b;
	b.handler->handle(makeRegister("200", "192.168.79.20"));   // front desk
	b.handler->setE911Config("200", "", "");
	b.handler->setTrunkConfig(trunkConfig());
	b.handler->setDialRule("0", "trunk", "911", 1);
	b.sent.clear();

	b.handler->handle(makeInvite("0", "er-rule-trunk-911"));

	EXPECT_EQ(b.count("INVITE sip:911@" + std::string(kSbcIp), kSbcIp), 1u) << b.dump();
	ASSERT_EQ(b.count("MESSAGE sip:200@"), 1u)
		<< "the front desk must hear about a 911 however it was dialed:\n" << b.dump();
	EXPECT_TRUE(b.saw("ROUTED TO TRUNK")) << b.dump();
	EXPECT_EQ(b.loopback()->lastMakeCallDestination(), "");
}

// ═════════════════════════════════════════════════════════════════════════════
// B. What #521 added.
// ═════════════════════════════════════════════════════════════════════════════

TEST(EmergencyRoute, TheReportedRouteIsNoneUntilARealProviderOrATrunkExists)
{
	Bench b;
	EXPECT_EQ(b.handler->emergencyRoute(), RequestsHandler::EmergencyRoute::None)
		<< "the loopback simulator is not a route";

	b.handler->setTrunkConfig(trunkConfig());
	EXPECT_EQ(b.handler->emergencyRoute(), RequestsHandler::EmergencyRoute::TrunkUnverified)
		<< "#546: configured, but no call has proved it yet";

	b.handler->setAnchorPlacesRealCallsForTest(true);
	EXPECT_EQ(b.handler->emergencyRoute(), RequestsHandler::EmergencyRoute::Anchor)
		<< "a real anchor is tried first; the trunk is its fallback";

	b.handler->setAnchorPlacesRealCallsForTest(false);
	b.handler->setTrunkConfig(SipTrunk::Config{});
	EXPECT_EQ(b.handler->emergencyRoute(), RequestsHandler::EmergencyRoute::None)
		<< "clearing the trunk takes the route away again";

	EXPECT_STREQ(RequestsHandler::emergencyRouteName(RequestsHandler::EmergencyRoute::None), "none");
	EXPECT_STREQ(RequestsHandler::emergencyRouteName(RequestsHandler::EmergencyRoute::Anchor), "anchor");
	EXPECT_STREQ(RequestsHandler::emergencyRouteName(RequestsHandler::EmergencyRoute::Trunk), "trunk");
	EXPECT_STREQ(RequestsHandler::emergencyRouteName(RequestsHandler::EmergencyRoute::TrunkUnverified),
		"trunk-unverified");
}

TEST(EmergencyRoute, OnlyTheTelephonyApiProviderPlacesRealCalls)
{
	EXPECT_FALSE(telephonyProviderPlacesRealCalls(TelephonyProviderType::Loopback))
		<< "implemented, but what it implements is a simulated answer";
	EXPECT_TRUE(telephonyProviderPlacesRealCalls(TelephonyProviderType::Telephony));
	EXPECT_FALSE(telephonyProviderPlacesRealCalls(TelephonyProviderType::Count))
		<< "anything not on the allowlist is assumed unable to carry 911";
}

TEST(EmergencyRoute, ARealAnchorTakesTheCallAheadOfTheTrunk)
{
	Bench b;
	b.handler->setTrunkConfig(trunkConfig());
	b.handler->setAnchorPlacesRealCallsForTest(true);

	b.handler->handle(makeInvite("911", "er-anchor"));

	EXPECT_EQ(b.loopback()->lastMakeCallDestination(), "911")
		<< "the (stand-in) real provider is asked to dial the bare number";
	EXPECT_EQ(b.count("INVITE sip:"), 0u)
		<< "and the carrier is not ALSO sent the call:\n" << b.dump();
}

TEST(EmergencyRoute, ARealAnchorThatIsDownFallsBackToTheTrunk)
{
	Bench b;
	b.handler->setTrunkConfig(trunkConfig());
	b.handler->setAnchorPlacesRealCallsForTest(true);
	b.handler->anchorClientForTest()->stop();
	ASSERT_FALSE(b.handler->anchorClientForTest()->isConnected());

	b.handler->handle(makeInvite("911", "er-fallback"));

	EXPECT_EQ(b.count("INVITE sip:911@" + std::string(kSbcIp), kSbcIp), 1u)
		<< "a down anchor must not strand a 911 call a working trunk could carry:\n"
		<< b.dump();
	EXPECT_EQ(b.count("SIP/2.0 503"), 0u) << b.dump();
}

TEST(EmergencyRoute, ARealAnchorThatIsDownWithNoTrunkSaysSo)
{
	Bench b;
	b.handler->setAnchorPlacesRealCallsForTest(true);
	b.handler->anchorClientForTest()->stop();

	b.handler->handle(makeInvite("911", "er-down"));

	EXPECT_EQ(b.count("SIP/2.0 503 Emergency Call Not Routable"), 1u) << b.dump();
	EXPECT_TRUE(b.saw("no outbound trunk connected"))
		<< "a configured provider that is down is not \"no route configured\"";
	EXPECT_FALSE(b.saw("no emergency route configured")) << b.dump();
}

TEST(EmergencyRoute, ACodecRejectedOfferIsNotRetriedOnTheTrunk)
{
	// The trunk relays the handset's audio without transcoding, so an offer the
	// anchor cannot carry is no better there. One 503 that says why.
	Bench b;
	b.handler->setTrunkConfig(trunkConfig());
	b.handler->setAnchorPlacesRealCallsForTest(true);

	b.handler->handle(makeInvite("911", "er-pcma", /*payloadType=*/8));

	EXPECT_EQ(b.count("SIP/2.0 503 Emergency Call Not Routable"), 1u) << b.dump();
	EXPECT_TRUE(b.saw("no G.711 codec offered")) << b.dump();
	EXPECT_EQ(b.count("INVITE sip:"), 0u) << b.dump();
}

TEST(EmergencyRoute, ATrunkOnlyBoardRefusesAnOfferItCannotRelay)
{
	// #538 review M1: the anchor's codec gate never runs on a trunk-only board,
	// and onTrunkAnswered answers PCMU whatever was offered. Without a gate of its
	// own the trunk connected a PCMA-only 911 with dead audio.
	Bench b;
	b.handler->setTrunkConfig(trunkConfig());

	b.handler->handle(makeInvite("911", "er-trunk-pcma", /*payloadType=*/8));

	EXPECT_EQ(b.count("SIP/2.0 503 Emergency Call Not Routable"), 1u) << b.dump();
	EXPECT_TRUE(b.saw("no G.711 codec offered")) << b.dump();
	EXPECT_EQ(b.count("INVITE sip:"), 0u)
		<< "the carrier must not be sent a call the handset cannot hear:\n" << b.dump();
	EXPECT_EQ(b.handler->trunkRelaysInUseForTest(), 0u);
}

TEST(EmergencyRoute, TheFrontDeskIsToldTheTrunkTookTheCall)
{
	// Kari's Law notification (#166) reports whether the call was ROUTED. On
	// the trunk path that is placeSipTrunkCall()'s placedOut, which only the
	// path that hands the call to the carrier sets.
	Bench b;
	b.handler->handle(makeRegister("200", "192.168.79.20"));   // front desk
	b.handler->setE911Config("200", "", "");
	b.handler->setTrunkConfig(trunkConfig());
	b.sent.clear();

	b.handler->handle(makeInvite("911", "er-notify-trunk"));

	ASSERT_EQ(b.count("MESSAGE sip:200@"), 1u) << b.dump();
	EXPECT_TRUE(b.saw("ROUTED TO TRUNK")) << b.dump();
	EXPECT_FALSE(b.saw("NOT ROUTED")) << b.dump();
}

TEST(EmergencyRoute, TheFrontDeskIsToldALoopbackOnlyBoardDidNotRouteIt)
{
	// THE defect, as the front desk saw it: before #521 this said ROUTED.
	Bench b;
	b.handler->handle(makeRegister("200", "192.168.79.20"));
	b.handler->setE911Config("200", "", "");
	b.sent.clear();

	b.handler->handle(makeInvite("911", "er-notify-loop"));

	ASSERT_EQ(b.count("MESSAGE sip:200@"), 1u) << b.dump();
	EXPECT_TRUE(b.saw("NOT ROUTED")) << b.dump();
	EXPECT_FALSE(b.saw("ROUTED TO TRUNK"))
		<< "a simulated answer reported to a human as a routed 911 call:\n" << b.dump();
}

TEST(EmergencyRoute, BootingWithNoRouteLogsAWarning)
{
	TrunkConfigStore::resetForTest();   // nothing stored: no trunk
	Bench b;

	testing::internal::CaptureStderr();
	b.handler->applyStoredTrunkConfig();   // what every esp_main variant does at boot
	b.handler->tick();                     // drains the queued log line
	const std::string log = testing::internal::GetCapturedStderr();

	EXPECT_NE(log.find("WARN: EMERGENCY CALLING IS NOT CONFIGURED"), std::string::npos)
		<< "the boot log must say 911 will be refused. Got:\n" << log;
	TrunkConfigStore::resetForTest();
}

TEST(EmergencyRoute, BootingWithAStoredTrunkLogsNoWarning)
{
	TrunkConfigStore::resetForTest();
	TrunkConfigStore::Config stored;
	stored.host = kSbcIp;
	stored.fromUser = "15551230000";
	stored.enabled = true;
	ASSERT_TRUE(TrunkConfigStore::save(stored));
	Bench b;

	testing::internal::CaptureStderr();
	b.handler->applyStoredTrunkConfig();
	b.handler->tick();
	const std::string log = testing::internal::GetCapturedStderr();

	EXPECT_EQ(b.handler->emergencyRoute(), RequestsHandler::EmergencyRoute::TrunkUnverified)
		<< "#546: a stored trunk is configured, not yet proved";
	EXPECT_EQ(log.find("EMERGENCY CALLING IS NOT CONFIGURED"), std::string::npos)
		<< "a board that can reach 911 must not cry wolf:\n" << log;
	TrunkConfigStore::resetForTest();
}

namespace
{
	std::string httpGet(int port, const std::string& path)
	{
#if defined(_WIN32) || defined(_WIN64)
		SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
		if (s == INVALID_SOCKET) return "";
#else
		int s = socket(AF_INET, SOCK_STREAM, 0);
		if (s < 0) return "";
#endif
		sockaddr_in addr{};
		addr.sin_family = AF_INET;
		addr.sin_port = htons(static_cast<uint16_t>(port));
		inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
		std::string resp;
		if (connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0)
		{
			const std::string req = "GET " + path + " HTTP/1.1\r\nHost: 127.0.0.1\r\n"
			                        "Connection: close\r\n\r\n";
			send(s, req.c_str(), static_cast<int>(req.size()), 0);
			char buf[512];
			int n;
			while ((n = recv(s, buf, sizeof(buf), 0)) > 0) resp.append(buf, static_cast<size_t>(n));
		}
#if defined(_WIN32) || defined(_WIN64)
		closesocket(s);
#else
		close(s);
#endif
		return resp;
	}
}

TEST(EmergencyRoute, StatusReportsTheRouteWithoutASession)
{
	AdminAuth::clearCredential();
	Bench b;
	constexpr int kPort = 18290;
	HttpServer server("127.0.0.1", kPort, nullptr);
	server.attachHandler(b.handler.get());
	server.start();
	std::this_thread::sleep_for(std::chrono::milliseconds(50));

	EXPECT_NE(httpGet(kPort, "/api/status").find("\"emergencyRoute\":\"none\""), std::string::npos)
		<< "the dashboard banner keys on this, and it must not need a login";

	b.handler->setTrunkConfig(trunkConfig());
	EXPECT_NE(httpGet(kPort, "/api/status").find("\"emergencyRoute\":\"trunk-unverified\""), std::string::npos)
		<< "#546: no carrier 2xx yet";

	b.handler->setAnchorPlacesRealCallsForTest(true);
	EXPECT_NE(httpGet(kPort, "/api/status").find("\"emergencyRoute\":\"anchor\""), std::string::npos);
	AdminAuth::clearCredential();
}

TEST(EmergencyRoute, TheDashboardShowsTheBannerWhileTheRouteIsNone)
{
	// The page's JS is not host-executable; this pins the wiring instead: the
	// banner exists, starts hidden, and fetchStatus() -- the once-a-second
	// status poll -- is what drives it.
	std::string page;
	for (const auto& part : CGA_INDEX_HTML_PARTS) page.append(part.data, part.size);

	const size_t banner = page.find("id=\"e911-route-banner\"");
	ASSERT_NE(banner, std::string::npos) << "no emergency-route banner on the dashboard";
	const size_t tagEnd = page.find('>', banner);
	EXPECT_NE(page.substr(banner, tagEnd - banner).find("display:none"), std::string::npos)
		<< "hidden until the board says the route is none";

	const size_t poll = page.find("function fetchStatus(){");
	ASSERT_NE(poll, std::string::npos);
	const size_t pollEnd = page.find("\n}\n", poll);
	EXPECT_NE(page.substr(poll, pollEnd - poll).find("applyEmergencyRoute(d)"), std::string::npos)
		<< "the status poll must drive the banner";
	EXPECT_NE(page.find("d.emergencyRoute===\"none\""), std::string::npos);
}

TEST(EmergencyRoute, TheDashboardWarnsWhileTheTrunkRouteIsUnverified)
{
	// #546: the unverified banner exists, starts hidden, and the status poll's
	// applyEmergencyRoute() shows it for exactly "trunk-unverified".
	std::string page;
	for (const auto& part : CGA_INDEX_HTML_PARTS) page.append(part.data, part.size);

	const size_t banner = page.find("id=\"e911-unverified-banner\"");
	ASSERT_NE(banner, std::string::npos) << "no unverified-route banner on the dashboard";
	const size_t tagEnd = page.find('>', banner);
	EXPECT_NE(page.substr(banner, tagEnd - banner).find("display:none"), std::string::npos);

	const size_t fn = page.find("function applyEmergencyRoute(d){");
	ASSERT_NE(fn, std::string::npos);
	const std::string body = page.substr(fn, page.find("\n}\n", fn) - fn);
	EXPECT_NE(body.find("e911-unverified-banner"), std::string::npos) << body;
	EXPECT_NE(body.find("d.emergencyRoute===\"trunk-unverified\""), std::string::npos) << body;
}

TEST(EmergencyRoute, TheE911BannerDefersToTheRouteBannerWhileTheRouteIsNone)
{
	// BigDog's be57113: a fresh board showed both banners at once, "911 still
	// routes out" (e911Configured false) beside "emergency calling is not
	// configured" (route none), which contradict each other. applyE911() hides
	// its banner while the route is none, and the status poll drives both.
	std::string page;
	for (const auto& part : CGA_INDEX_HTML_PARTS) page.append(part.data, part.size);

	const size_t fn = page.find("function applyE911(");
	ASSERT_NE(fn, std::string::npos);
	const size_t fnEnd = page.find('\n', fn);
	const std::string body = page.substr(fn, fnEnd - fn);
	EXPECT_NE(body.find("e911-banner"), std::string::npos) << body;
	EXPECT_NE(body.find("d.emergencyRoute===\"none\""), std::string::npos)
		<< "the E911 banner must stand down while the route banner is up:\n" << body;

	const size_t poll = page.find("function fetchStatus(){");
	ASSERT_NE(poll, std::string::npos);
	const std::string pollBody = page.substr(poll, page.find("\n}\n", poll) - poll);
	EXPECT_NE(pollBody.find("applyE911(d)"), std::string::npos);
	EXPECT_NE(pollBody.find("applyEmergencyRoute(d)"), std::string::npos);
}

TEST(EmergencyRoute, ALoopbackOnlyBoardSaysNoRouteEvenForAnOfferItCouldNotCarry)
{
	// The M1 codec gate belongs to the trunk branch. With no route at all the
	// honest reason is "no emergency route configured", whatever was offered.
	Bench b;

	b.handler->handle(makeInvite("911", "er-loop-pcma", /*payloadType=*/8));

	EXPECT_EQ(b.count("SIP/2.0 503 Emergency Call Not Routable"), 1u) << b.dump();
	EXPECT_TRUE(b.saw("no emergency route configured")) << b.dump();
	EXPECT_FALSE(b.saw("no G.711 codec offered")) << b.dump();
}

// ═════════════════════════════════════════════════════════════════════════════
// #550: no extension may be named like an emergency number.
// ═════════════════════════════════════════════════════════════════════════════

TEST(EmergencyRoute, TheWholeEmergencySetIsReserved)
{
	for (const char* aor : {"911", "933", "9911", "9933"})
	{
		SCOPED_TRACE(aor);
		EXPECT_TRUE(pbx::isReservedExtension(aor));
		EXPECT_TRUE(pbx::isReservedOrPstnAor(aor));
	}
	for (const char* aor : {"912", "9912", "99111", "1911", "201"})
	{
		SCOPED_TRACE(aor);
		EXPECT_FALSE(pbx::isReservedExtension(aor)) << "only the emergency set, nothing near it";
	}
}

TEST(EmergencyRoute, APhoneCannotRegisterUnderAPrefixedEmergencyNumber)
{
	Bench b;

	b.handler->handle(makeRegister("9911"));

	EXPECT_EQ(b.count("SIP/2.0 403"), 1u) << b.dump();
	EXPECT_EQ(b.count("SIP/2.0 200"), 0u) << "9911 dials 911; it can't be an extension:\n" << b.dump();
}

TEST(EmergencyRoute, The555OwnNumberDialCannotHandTheLoopbackAnEmergencyNumber)
{
	// The state #550 now forbids, forced through a seam: a client named 9911
	// dials 555, whose destination is the caller's own number. The loopback
	// guard in originateAnchorCall() is the backstop that must still refuse.
	Bench b;
	b.handler->bindClientBypassingGuardsForTest("9911", addrFor(kHandsetIp));
	const std::string body =
		"v=0\r\no=- 0 0 IN IP4 " + std::string(kHandsetIp) + "\r\ns=-\r\n"
		"c=IN IP4 " + std::string(kHandsetIp) + "\r\nt=0 0\r\n"
		"m=audio 40000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n";
	const std::string raw =
		"INVITE sip:555@server SIP/2.0\r\n"
		"Via: SIP/2.0/UDP " + std::string(kHandsetIp) + ":5060;branch=z9hG4bKer550\r\n"
		"From: <sip:9911@server>;tag=er550\r\n"
		"To: <sip:555@server>\r\n"
		"Call-ID: er-550\r\n"
		"CSeq: 1 INVITE\r\n"
		"Max-Forwards: 70\r\n"
		"Contact: <sip:9911@" + std::string(kHandsetIp) + ":5060>\r\n"
		"Content-Type: application/sdp\r\n"
		"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;

	b.handler->handle(RequestsHandler::getMessageFromPool(raw, addrFor(kHandsetIp)));

	EXPECT_EQ(b.loopback()->lastMakeCallDestination(), "")
		<< "the simulator must never be asked to dial 9911";
	EXPECT_EQ(b.count("SIP/2.0 503 Emergency Call Not Routable"), 1u) << b.dump();
	EXPECT_EQ(b.count("SIP/2.0 200"), 0u) << b.dump();
}

// ═════════════════════════════════════════════════════════════════════════════
// D. #553/#608: a 911 dialed in the rx-cancel window is not refused.
// ═════════════════════════════════════════════════════════════════════════════

TEST(EmergencyRoute, ANineOneOneDialedWhileTheLastAnchorLegIsCancellingIsPlaced)
{
	// The window: endCall() stops the MediaBridge and drops the leg, and on
	// firmware dropCall() -> stopMediaStreams() then waits up to 2 s for the rx
	// task to park, holding only TelephonyAnchorClient's own slot (#553). The
	// engine's admission (allBridgesBusy) counts MediaBridges, never that slot,
	// so a 911 right after the BYE must be placed, not given the busy 503.
	// Loopback stands in for the real provider (as in section A's neighbours).
	Bench b;
	b.handler->setAnchorPlacesRealCallsForTest(true);

	b.handler->handle(makeInvite("555", "er-win-1"));
	ASSERT_EQ(b.count("SIP/2.0 200"), 1u) << "the first anchored call must connect:\n" << b.dump();

	const std::string bye =
		"BYE sip:555@server SIP/2.0\r\n"
		"Via: SIP/2.0/UDP " + std::string(kHandsetIp) + ":5060;branch=z9hG4bKerwinbye\r\n"
		"From: <sip:101@server>;tag=efer-win-1\r\n"
		"To: <sip:555@server>;tag=srv\r\n"
		"Call-ID: er-win-1\r\n"
		"CSeq: 2 BYE\r\n"
		"Content-Length: 0\r\n\r\n";
	b.handler->handle(RequestsHandler::getMessageFromPool(bye, addrFor(kHandsetIp)));
	ASSERT_EQ(b.loopback()->dropCallCount(), 1u) << "the leg's cancel must have started (the window opener)";

	b.sent.clear();
	b.handler->handle(makeInvite("911", "er-win-911"));

	EXPECT_EQ(b.count("SIP/2.0 503"), 0u)
		<< "911 in the rx-cancel window was refused:\n" << b.dump();
	EXPECT_EQ(b.loopback()->lastMakeCallDestination(), "911")
		<< "the provider must be asked to dial 911, as outside the window";
	EXPECT_EQ(b.count("SIP/2.0 200"), 1u) << b.dump();
}

// ═════════════════════════════════════════════════════════════════════════════
// E. #624: a 911 on a full anchor pre-empts one NON-emergency anchored leg.
// ═════════════════════════════════════════════════════════════════════════════
//
// The host anchor is Loopback, so the anchor holds one call (anchorCallLimit()
// is 1), the same as a SIP_CONSTRAINED board. Loopback stands in for the real
// provider, as in section D. 102 on a second phone holds the slot; 101 dials.

namespace
{
	constexpr const char* kOtherIp = "192.168.79.12";

	// A Bench whose loopback counts as a real provider, with 102 registered.
	void preemptBench(Bench& b)
	{
		b.handler->setAnchorPlacesRealCallsForTest(true);
		b.handler->handle(makeRegister("102", kOtherIp));
		b.sent.clear();
	}
}

TEST(EmergencyRoute, ANineOneOneOnAFullAnchorPreEmptsANormalCall)
{
	Bench b;
	preemptBench(b);
	b.handler->handle(makeInvite("555", "er-pre-1", 0, "102", kOtherIp));
	ASSERT_EQ(b.count("SIP/2.0 200", kOtherIp), 1u) << "102's call must hold the bridge:\n" << b.dump();
	b.sent.clear();

	b.handler->handle(makeInvite("911", "er-pre-911"));

	EXPECT_EQ(b.count("SIP/2.0 503"), 0u) << "911 refused on a full anchor:\n" << b.dump();
	EXPECT_EQ(b.loopback()->lastMakeCallDestination(), "911");
	EXPECT_EQ(b.count("SIP/2.0 200", kHandsetIp), 1u) << b.dump();
	EXPECT_EQ(b.count("BYE sip:102@", kOtherIp), 1u) << "the pre-empted caller gets a BYE:\n" << b.dump();
	EXPECT_EQ(b.loopback()->dropCallCount(), 1u) << "exactly one anchored leg is dropped";
	EXPECT_FALSE(b.handler->getSession("Call-ID: er-pre-1").has_value());
	auto s = b.handler->getSession("Call-ID: er-pre-911");
	ASSERT_TRUE(s.has_value()) << b.dump();
	EXPECT_TRUE(s.value()->isEmergency());
	EXPECT_NE(b.handler->anchorBridgeForCallIdForTest("Call-ID: er-pre-911"), nullptr);
}

TEST(EmergencyRoute, ANineOneOneNeverPreEmptsAnotherEmergencyCall)
{
	Bench b;
	preemptBench(b);
	b.handler->handle(makeInvite("911", "er-pre-e1", 0, "102", kOtherIp));
	// Positive control: the first 911 is up, flagged, and holds the only bridge.
	auto first = b.handler->getSession("Call-ID: er-pre-e1");
	ASSERT_TRUE(first.has_value()) << b.dump();
	ASSERT_TRUE(first.value()->isEmergency());
	ASSERT_NE(b.handler->anchorBridgeForCallIdForTest("Call-ID: er-pre-e1"), nullptr);
	b.sent.clear();

	b.handler->handle(makeInvite("911", "er-pre-e2"));

	EXPECT_EQ(b.count("SIP/2.0 503", kHandsetIp), 1u) << b.dump();
	EXPECT_EQ(b.count("BYE"), 0u) << "an emergency call was pre-empted:\n" << b.dump();
	EXPECT_EQ(b.loopback()->dropCallCount(), 0u);
	EXPECT_TRUE(b.handler->getSession("Call-ID: er-pre-e1").has_value());
	EXPECT_NE(b.handler->anchorBridgeForCallIdForTest("Call-ID: er-pre-e1"), nullptr);
}

TEST(EmergencyRoute, ANineOneOnePreEmptsARingingLegHoldingTheOnlySlot)
{
	// #667: a ringing outbound leg holds the provider's slot but no bridge, and
	// one that vanishes in its 120 s ringing grace keeps holding it. The async
	// path's shape is recreated on the session (as AnchorRouting's #548 test
	// does): Invited, bridge stopped, its INVITE stored for the final answer.
	Bench b;
	preemptBench(b);
	b.handler->handle(makeInvite("555", "er-ring-1", 0, "102", kOtherIp));
	auto ringing = b.handler->getSession("Call-ID: er-ring-1");
	ASSERT_TRUE(ringing.has_value()) << b.dump();
	ringing.value()->setState(Session::State::Invited);
	ringing.value()->setInviteMessage(makeInvite("555", "er-ring-1", 0, "102", kOtherIp));
	b.handler->anchorBridgeForCallIdForTest("Call-ID: er-ring-1")->stopBridge();
	b.sent.clear();

	b.handler->handle(makeInvite("911", "er-ring-911"));

	EXPECT_EQ(b.loopback()->dropCallCount(), 1u) << "the ringing leg's slot must be freed";
	EXPECT_FALSE(b.handler->getSession("Call-ID: er-ring-1").has_value());
	EXPECT_EQ(b.count("SIP/2.0 503", kOtherIp), 1u) << "the ringing caller gets a final answer:\n" << b.dump();
	EXPECT_EQ(b.count("BYE"), 0u) << "a call still ringing gets its 503, not a BYE:\n" << b.dump();
	EXPECT_EQ(b.count("SIP/2.0 503", kHandsetIp), 0u) << b.dump();
	EXPECT_EQ(b.count("SIP/2.0 200", kHandsetIp), 1u) << b.dump();
	EXPECT_EQ(b.loopback()->lastMakeCallDestination(), "911");
}

TEST(EmergencyRoute, ANineOneOnePreEmptsARingingInboundCallAndCancelsItsForks)
{
	// A PSTN call still ringing the extensions holds the only slot as well.
	Bench b;
	preemptBench(b);
	const std::string inbound = b.handler->routeInboundAnchorCallForTest("106", "part-in-624", "5551234567");
	ASSERT_FALSE(inbound.empty()) << "precondition: an inbound anchored call is ringing";
	b.handler->tick();   // drainOutbox() sends the fork INVITEs from _asyncOutbox
	ASSERT_EQ(b.count("INVITE sip:102@", kOtherIp), 1u) << "precondition: 102 is rung:\n" << b.dump();
	b.sent.clear();

	b.handler->handle(makeInvite("911", "er-in-911"));

	EXPECT_EQ(b.count("CANCEL sip:102@", kOtherIp), 1u) << "102 must stop ringing:\n" << b.dump();
	EXPECT_EQ(b.loopback()->dropCallCount(), 1u) << "the PSTN leg is dropped";
	EXPECT_FALSE(b.handler->getSession(inbound).has_value());
	EXPECT_EQ(b.count("SIP/2.0 200", kHandsetIp), 1u) << b.dump();
	EXPECT_EQ(b.loopback()->lastMakeCallDestination(), "911");

}
// ═════════════════════════════════════════════════════════════════════════════
// F. #659: a call to an extension that dialed 911/933 in the last 30 minutes is
// a PSAP callback, and so an emergency call. The 911 goes to the loopback anchor
// posing as a real provider; the callback is an inbound anchor event or an
// internal call. Nothing leaves the process.
// ═════════════════════════════════════════════════════════════════════════════

namespace
{
	constexpr const char* kThirdIp = "192.168.79.13";

	std::shared_ptr<SipMessage> makeCall(const std::string& from, const char* ip,
		const std::string& to, const std::string& callId)
	{
		const std::string body =
			"v=0\r\no=- 0 0 IN IP4 " + std::string(ip) + "\r\ns=-\r\n"
			"c=IN IP4 " + std::string(ip) + "\r\nt=0 0\r\n"
			"m=audio 40000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n";
		const std::string raw =
			"INVITE sip:" + to + "@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + std::string(ip) + ":5060;branch=z9hG4bK" + callId + "\r\n"
			"From: <sip:" + from + "@server>;tag=f" + callId + "\r\n"
			"To: <sip:" + to + "@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Max-Forwards: 70\r\n"
			"Contact: <sip:" + from + "@" + std::string(ip) + ":5060>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		return RequestsHandler::getMessageFromPool(raw, addrFor(ip));
	}

	// 101 dials 911, then hangs up: no emergency call is live afterwards.
	void dial911AndHangUp(Bench& b)
	{
		b.handler->setAnchorPlacesRealCallsForTest(true);
		b.handler->handle(makeInvite("911", "er-659"));
		ASSERT_EQ(b.loopback()->lastMakeCallDestination(), "911") << b.dump();
		b.handler->handle(RequestsHandler::getMessageFromPool(
			"BYE sip:911@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + std::string(kHandsetIp) + ":5060;branch=z9hG4bKer659bye\r\n"
			"From: <sip:101@server>;tag=efer-659\r\n"
			"To: <sip:911@server>;tag=srv\r\n"
			"Call-ID: er-659\r\nCSeq: 2 BYE\r\nContent-Length: 0\r\n\r\n", addrFor(kHandsetIp)));
		ASSERT_FALSE(b.handler->hasLiveEmergencyCall()) << "precondition: the 911 has ended";
	}
}

TEST(EmergencyCallback, AnAnchorCallbackWithinThirtyMinutesIsAnEmergencyCall)
{
	Bench b;
	ASSERT_NO_FATAL_FAILURE(dial911AndHangUp(b));
	b.handler->ageEmergencyCallbacksForTest(std::chrono::minutes(29));

	const std::string id = b.handler->routeInboundAnchorCallForTest("800", "psap-659", "PSAP");
	const auto s = b.handler->getSession(id);
	ASSERT_TRUE(s.has_value()) << "the callback must ring 101:\n" << b.dump();
	EXPECT_TRUE(s.value()->isEmergency()) << "29 min after the 911, a call to 101 is a PSAP callback";
}

TEST(EmergencyCallback, AnInternalCallbackWithinThirtyMinutesIsAnEmergencyCall)
{
	Bench b;
	b.handler->handle(makeRegister("102", kOtherIp));
	ASSERT_NO_FATAL_FAILURE(dial911AndHangUp(b));

	b.handler->handle(makeCall("102", kOtherIp, "101", "er-659-in"));
	const auto s = b.handler->getSession("Call-ID: er-659-in");
	ASSERT_TRUE(s.has_value()) << b.dump();
	EXPECT_TRUE(s.value()->isEmergency());
}

TEST(EmergencyCallback, ACallbackAfterThirtyMinutesIsNot)
{
	Bench b;
	b.handler->handle(makeRegister("102", kOtherIp));
	ASSERT_NO_FATAL_FAILURE(dial911AndHangUp(b));

	b.handler->ageEmergencyCallbacksForTest(std::chrono::minutes(29));
	b.handler->handle(makeCall("102", kOtherIp, "101", "er-659-29"));
	const auto inside = b.handler->getSession("Call-ID: er-659-29");
	ASSERT_TRUE(inside.has_value()) << b.dump();
	ASSERT_TRUE(inside.value()->isEmergency()) << "control: flagged inside the window";

	b.handler->ageEmergencyCallbacksForTest(std::chrono::minutes(2));
	b.handler->handle(makeCall("102", kOtherIp, "101", "er-659-31"));
	const auto after = b.handler->getSession("Call-ID: er-659-31");
	ASSERT_TRUE(after.has_value()) << b.dump();
	EXPECT_FALSE(after.value()->isEmergency()) << "31 min after the 911 the window has closed";
}

TEST(EmergencyCallback, ACallToAnotherExtensionIsNot)
{
	Bench b;
	b.handler->handle(makeRegister("102", kOtherIp));
	b.handler->handle(makeRegister("103", kThirdIp));
	ASSERT_NO_FATAL_FAILURE(dial911AndHangUp(b));

	b.handler->handle(makeCall("103", kThirdIp, "102", "er-659-other"));
	b.handler->handle(makeCall("101", kHandsetIp, "102", "er-659-out"));
	b.handler->handle(makeCall("103", kThirdIp, "101", "er-659-ctl"));
	const auto other = b.handler->getSession("Call-ID: er-659-other");
	const auto out = b.handler->getSession("Call-ID: er-659-out");
	const auto ctl = b.handler->getSession("Call-ID: er-659-ctl");
	ASSERT_TRUE(other.has_value() && out.has_value() && ctl.has_value()) << b.dump();
	EXPECT_FALSE(other.value()->isEmergency()) << "102 never dialed 911";
	EXPECT_FALSE(out.value()->isEmergency()) << "a call FROM the 911 caller is not a callback";
	EXPECT_TRUE(ctl.value()->isEmergency()) << "control: the same call to 101 is flagged";
}

// ═════════════════════════════════════════════════════════════════════════════
// #760: the two emergency INVITE shapes a phone may legitimately send
// ═════════════════════════════════════════════════════════════════════════════

namespace
{
	// An INVITE from 101 with a caller-chosen Request-URI, To URI and body.
	std::shared_ptr<SipMessage> makeShapedInvite(const std::string& requestUri,
		const std::string& toUri, const std::string& contentType,
		const std::string& extraHeaders, const std::string& body, const std::string& callId)
	{
		const std::string raw =
			"INVITE " + requestUri + " SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + std::string(kHandsetIp) + ":5060;branch=z9hG4bKei" + callId + "\r\n"
			"From: <sip:101@server>;tag=ef" + callId + "\r\n"
			"To: <" + toUri + ">\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Max-Forwards: 70\r\n"
			"Contact: <sip:101@" + std::string(kHandsetIp) + ":5060>\r\n" +
			extraHeaders +
			"Content-Type: " + contentType + "\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		return RequestsHandler::getMessageFromPool(raw, addrFor(kHandsetIp));
	}

	const std::string kSdpOffer =
		"v=0\r\n"
		"o=- 0 0 IN IP4 192.168.79.11\r\n"
		"s=-\r\n"
		"c=IN IP4 192.168.79.11\r\n"
		"t=0 0\r\n"
		"m=audio 40000 RTP/AVP 0\r\n"
		"a=rtpmap:0 PCMU/8000\r\n";

	// RFC 6442's shape: the SDP offer, then a PIDF-LO (RFC 4119) civic location.
	std::string multipartWithLocation(const std::string& boundary)
	{
		return
			"--" + boundary + "\r\n"
			"Content-Type: application/sdp\r\n"
			"\r\n" + kSdpOffer +
			"--" + boundary + "\r\n"
			"Content-Type: application/pidf+xml\r\n"
			"Content-ID: <target101@pd.example>\r\n"
			"\r\n"
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"
			"<presence xmlns=\"urn:ietf:params:xml:ns:pidf\" entity=\"pres:101@pd.example\">\r\n"
			"<tuple id=\"t1\"><status><gp:geopriv xmlns:gp=\"urn:ietf:params:xml:ns:pidf:geopriv10\">"
			"<gp:location-info><ca:civicAddress xmlns:ca=\"urn:ietf:params:xml:ns:pidf:geopriv10:civicAddr\">"
			"<ca:country>US</ca:country><ca:A1>NY</ca:A1><ca:FLR>2</ca:FLR></ca:civicAddress>"
			"</gp:location-info></gp:geopriv></status></tuple>\r\n"
			"</presence>\r\n"
			"--" + boundary + "--\r\n";
	}

	// The carrier's 180 to the trunk INVITE it was sent for `number`, so the
	// dialog is Proceeding and a CANCEL may follow (RFC 3261 s9.1).
	std::shared_ptr<SipMessage> carrierRinging(const Bench& b, const std::string& number)
	{
		std::string invite;
		for (const auto& p : b.sent)
		{
			if (p.second.rfind("INVITE sip:" + number + "@", 0) == 0) { invite = p.second; break; }
		}
		auto between = [&invite](const std::string& open) {
			const size_t s = invite.find(open);
			if (s == std::string::npos) return std::string();
			const size_t from = s + open.size();
			return invite.substr(from, invite.find("\r\n", from) - from);
		};
		const std::string raw =
			"SIP/2.0 180 Ringing\r\n"
			"Via: SIP/2.0/UDP " + std::string(kServerIp) + ":5060;branch=" + between(";branch=") + "\r\n"
			"From: <sip:15551230000@" + std::string(kSbcIp) + ":5060>;tag=" + between(";tag=") + "\r\n"
			"To: <sip:" + number + "@" + std::string(kSbcIp) + ":5060>;tag=psap\r\n"
			"Call-ID: " + between("Call-ID: ") + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addrFor(kSbcIp));
	}
}

TEST(EmergencyRoute, AMultipartEmergencyInviteCarryingLocationIsRoutedNotRefused)
{
	// RFC 6442 (RAY BAUM'S Act dispatchable location): the phone puts its SDP
	// and a PIDF-LO in one multipart/mixed body. The T-7 SDP gate read the MIME
	// boundary as a malformed SDP line and answered a 911 with 488.
	for (const char* dialed : {"911", "933"})
	{
		SCOPED_TRACE(dialed);
		Bench b;
		b.handler->setTrunkConfig(trunkConfig());
		const std::string number(dialed);
		b.handler->handle(makeShapedInvite("sip:" + number + "@server", "sip:" + number + "@server",
			"multipart/mixed; boundary=pdloc1",
			"Geolocation: <cid:target101@pd.example>\r\nGeolocation-Routing: no\r\n",
			multipartWithLocation("pdloc1"), "er-mp-" + number));

		EXPECT_EQ(b.count("SIP/2.0 488"), 0u) << "the emergency offer was refused:\n" << b.dump();
		EXPECT_EQ(b.count("SIP/2.0 4"), 0u) << b.dump();
		EXPECT_EQ(b.count("SIP/2.0 5"), 0u) << b.dump();
		EXPECT_EQ(b.count("INVITE sip:" + number + "@" + kSbcIp, kSbcIp), 1u)
			<< "the carrier gets exactly one INVITE for the bare number:\n" << b.dump();
		EXPECT_EQ(b.count("SIP/2.0 180", kHandsetIp), 1u) << b.dump();
		EXPECT_FALSE(b.saw("pdloc1")) << "the MIME boundary must not reach the carrier's offer";
	}
}

TEST(EmergencyRoute, AMultipartEmergencyInviteIsRoutedOverTheAnchorToo)
{
	// The offer is unwrapped in handle(), before any route reads the body, so
	// the anchor route (no trunk) gets the plain SDP as well: its codec gate
	// and RTP parse see the offer, not the MIME wrapper.
	Bench b;
	b.handler->setAnchorPlacesRealCallsForTest(true);
	b.handler->handle(makeShapedInvite("sip:911@server", "sip:911@server",
		"multipart/mixed; boundary=pdloc3", "Geolocation: <cid:target101@pd.example>\r\n",
		multipartWithLocation("pdloc3"), "er-mp-anchor"));

	EXPECT_EQ(b.loopback()->lastMakeCallDestination(), "911") << b.dump();
	EXPECT_EQ(b.count("SIP/2.0 4"), 0u) << b.dump();
	EXPECT_EQ(b.count("SIP/2.0 5"), 0u) << b.dump();
	EXPECT_EQ(b.count("SIP/2.0 200", kHandsetIp), 1u) << "the (synchronous) anchor answered:\n" << b.dump();
	EXPECT_NE(b.handler->anchorBridgeForCallIdForTest("Call-ID: er-mp-anchor"), nullptr)
		<< "with a media bridge to the SDP part's c=/m= address";
}

TEST(EmergencyRoute, ATelUriOrTestServiceUrnEmergencyInviteIsRoutedNotRefused)
{
	// RFC 3966 tel:911 has no host and no @, so it read as no user at all and
	// was answered 400 Bad Request. RFC 5031's urn:service:test.sos is the
	// E911 test service, 933 here.
	struct Shape { const char* uri; const char* bare; };
	for (const Shape s : {Shape{"tel:911", "911"}, Shape{"tel:933", "933"},
	                      Shape{"urn:service:test.sos", "933"},
	                      Shape{"urn:service:test.sos.fire", "933"}})
	{
		SCOPED_TRACE(s.uri);
		Bench b;
		b.handler->setTrunkConfig(trunkConfig());
		b.handler->handle(makeShapedInvite(s.uri, s.uri, "application/sdp", "", kSdpOffer,
			std::string("er-uri-") + s.bare + std::to_string(std::string(s.uri).size())));

		EXPECT_EQ(b.count("SIP/2.0 400"), 0u) << "the emergency URI was refused:\n" << b.dump();
		EXPECT_EQ(b.count("INVITE sip:" + std::string(s.bare) + "@" + kSbcIp, kSbcIp), 1u)
			<< "the carrier gets exactly one INVITE for the bare number:\n" << b.dump();
		EXPECT_EQ(b.count("SIP/2.0 180", kHandsetIp), 1u) << b.dump();
	}
}

TEST(EmergencyRoute, ATelUriEmergencyCallIsStillEndedByItsCancel)
{
	// tel:911 now reads as 911 for every request on the dialog. The handset's
	// CANCEL (same Request-URI and To as its INVITE, RFC 3261 s9.1) still ends
	// the call exactly once: 200 to the CANCEL, 487 to the INVITE, a CANCEL to
	// the carrier, and no session left.
	Bench b;
	b.handler->setTrunkConfig(trunkConfig());
	b.handler->handle(makeShapedInvite("tel:911", "tel:911", "application/sdp", "", kSdpOffer,
		"er-tel-cancel"));
	ASSERT_EQ(b.count("INVITE sip:911@" + std::string(kSbcIp), kSbcIp), 1u) << b.dump();
	b.handler->handle(carrierRinging(b, "911"));
	b.sent.clear();

	b.handler->handle(RequestsHandler::getMessageFromPool(
		"CANCEL tel:911 SIP/2.0\r\n"
		"Via: SIP/2.0/UDP " + std::string(kHandsetIp) + ":5060;branch=z9hG4bKeier-tel-cancel\r\n"
		"From: <sip:101@server>;tag=efer-tel-cancel\r\n"
		"To: <tel:911>\r\n"
		"Call-ID: er-tel-cancel\r\n"
		"CSeq: 1 CANCEL\r\n"
		"Max-Forwards: 70\r\n"
		"Content-Length: 0\r\n\r\n", addrFor(kHandsetIp)));

	EXPECT_EQ(b.count("SIP/2.0 200", kHandsetIp), 1u) << "the CANCEL itself:\n" << b.dump();
	EXPECT_EQ(b.count("SIP/2.0 487", kHandsetIp), 1u) << "the handset's INVITE:\n" << b.dump();
	EXPECT_EQ(b.count("CANCEL sip:911@" + std::string(kSbcIp), kSbcIp), 1u)
		<< "the carrier leg is cancelled:\n" << b.dump();
	EXPECT_FALSE(b.handler->getSession("Call-ID: er-tel-cancel").has_value());
}

TEST(EmergencyRoute, ANonEmergencyMultipartOrTelInviteIsStillRefusedAsToday)
{
	// Positive control for the two tests above: the gate and the URI reader
	// yield for an emergency call only. A multipart body to an extension is
	// still refused (488 or 415), and a non-emergency tel: URI
	// still reads as no user (400). Nothing reaches the carrier.
	Bench b;
	b.handler->setTrunkConfig(trunkConfig());
	b.handler->handle(makeRegister("102", "192.168.79.12"));
	b.sent.clear();

	b.handler->handle(makeShapedInvite("sip:102@server", "sip:102@server",
		"multipart/mixed; boundary=pdloc2", "", multipartWithLocation("pdloc2"), "er-mp-102"));
	EXPECT_EQ(b.count("SIP/2.0 488") + b.count("SIP/2.0 415"), 1u)
		<< "refused (488 from the SDP gate today, 415 from #759's header gate):\n" << b.dump();
	EXPECT_EQ(b.count("SIP/2.0 180"), 0u) << b.dump();
	EXPECT_EQ(b.count("INVITE", kSbcIp), 0u) << b.dump();
	b.sent.clear();

	b.handler->handle(makeShapedInvite("tel:+15551230100", "tel:+15551230100",
		"application/sdp", "", kSdpOffer, "er-tel-plain"));
	EXPECT_EQ(b.count("SIP/2.0 400"), 1u) << b.dump();
	EXPECT_EQ(b.count("INVITE", kSbcIp), 0u) << b.dump();
}
