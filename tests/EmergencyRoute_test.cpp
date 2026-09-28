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
		int payloadType = 0)
	{
		const std::string rtpmap = payloadType == 8 ? "a=rtpmap:8 PCMA/8000\r\n"
		                                            : "a=rtpmap:0 PCMU/8000\r\n";
		const std::string body =
			"v=0\r\n"
			"o=- 0 0 IN IP4 " + std::string(kHandsetIp) + "\r\n"
			"s=-\r\n"
			"c=IN IP4 " + std::string(kHandsetIp) + "\r\n"
			"t=0 0\r\n"
			"m=audio 40000 RTP/AVP " + std::to_string(payloadType) + "\r\n" + rtpmap;
		const std::string raw =
			"INVITE sip:" + dialed + "@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + std::string(kHandsetIp) + ":5060;branch=z9hG4bKei" + callId + "\r\n"
			"From: <sip:101@server>;tag=ef" + callId + "\r\n"
			"To: <sip:" + dialed + "@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Max-Forwards: 70\r\n"
			"Contact: <sip:101@" + std::string(kHandsetIp) + ":5060>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		return RequestsHandler::getMessageFromPool(raw, addrFor(kHandsetIp));
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
