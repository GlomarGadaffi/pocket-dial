// ServiceExtensions_test.cpp — Issue #202: the engine-owned alphanumeric
// pseudo-AORs (`pbx`, `moh`, `server`) and the guards that keep them the
// engine's.
//
// What is under test here is NOT "voicemail works". It is the three properties
// the issue says a service extension must have before anything can be built on
// one, each of which was violable before this table existed:
//
//   1. The names are RESERVED. isValidAor has always admitted letters, so every
//      config surface that takes an extension — ring group, dial-plan pattern,
//      call forward, DID map, DND — would happily accept "pbx" and shadow an
//      identity the engine originates as.
//   2. They are NOT REGISTERABLE. A phone could REGISTER as `pbx` and take the
//      name outright; the register-beep response paths depend by name on
//      findClient("pbx") MISSING, so that binding would have made the PBX mint
//      404s back at phones it had just beeped.
//   3. Dialability is a PER-SERVICE FLAG, and every seeded service is currently
//      false. The last test in this file is the guard on that: nothing may be
//      routed to a service the engine cannot yet deliver to, and flipping a seed
//      to dialable without building the dispatch it needs must break a test
//      rather than silently start black-holing calls. See ServiceExtensions.hpp
//      for why the loopback dispatch the issue proposes does not work yet (the
//      cloned INVITE is dropped by onInvite's own retransmission guard).

#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "AdminAuth.hpp"
#include "HttpServer.hpp"
#include "RequestsHandler.hpp"
#include "ServiceExtensions.hpp"

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

#include <chrono>
#include <cstdlib>
#include <thread>

namespace
{
	sockaddr_in svcAddr(const std::string& ip)
	{
		sockaddr_in s{};
		s.sin_family = AF_INET;
		s.sin_addr.s_addr = inet_addr(ip.c_str());
		s.sin_port = htons(5060);
		return s;
	}

	std::shared_ptr<SipMessage> svcRegister(const std::string& ext, const std::string& srcIp,
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
		return RequestsHandler::getMessageFromPool(raw, svcAddr(srcIp));
	}

	std::shared_ptr<SipMessage> svcInvite(const std::string& fromExt, const std::string& toExt,
	                                      const std::string& srcIp, const std::string& callId)
	{
		std::string body =
			"v=0\r\n"
			"o=- 0 0 IN IP4 " + srcIp + "\r\n"
			"s=-\r\n"
			"c=IN IP4 " + srcIp + "\r\n"
			"t=0 0\r\n"
			"m=audio 10000 RTP/AVP 0 101\r\n"
			"a=rtpmap:0 PCMU/8000\r\n"
			"a=rtpmap:101 telephone-event/8000\r\n"
			"a=sendrecv\r\n";
		std::string raw =
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
		return RequestsHandler::getMessageFromPool(raw, svcAddr(srcIp));
	}

	// Records everything the handler puts on the wire so a test can assert on what
	// a dialed number actually produced rather than on internal state.
	struct SvcWire
	{
		std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>> sent;

		void clear() { sent.clear(); }

		std::vector<std::string> raws() const
		{
			std::vector<std::string> out;
			out.reserve(sent.size());
			for (const auto& entry : sent)
			{
				out.push_back(entry.second ? entry.second->toString() : std::string{});
			}
			return out;
		}

		bool sawContaining(const std::string& needle) const
		{
			for (const auto& raw : raws())
			{
				if (raw.find(needle) != std::string::npos) return true;
			}
			return false;
		}

		bool sawRequestTo(const std::string& method, const std::string& ext) const
		{
			for (const auto& raw : raws())
			{
				if (raw.rfind(method + " sip:" + ext + "@", 0) == 0) return true;
			}
			return false;
		}
	};

	bool hasRingGroup(RequestsHandler& h, const std::string& ext)
	{
		for (const auto& g : h.getRingGroups())
		{
			if (std::get<0>(g) == ext) return true;
		}
		return false;
	}

	bool hasDialRule(RequestsHandler& h, const std::string& pattern)
	{
		for (const auto& r : h.getDialRules())
		{
			if (std::get<0>(r) == pattern) return true;
		}
		return false;
	}

	// {always, busy, noanswer} for `ext`, or three empty strings when the table
	// holds no entry for it.
	std::tuple<std::string, std::string, std::string> forwardsOf(RequestsHandler& h,
	                                                             const std::string& ext)
	{
		for (const auto& f : h.getForwards())
		{
			if (std::get<0>(f) == ext)
			{
				return { std::get<1>(f), std::get<2>(f), std::get<3>(f) };
			}
		}
		return { "", "", "" };
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// 1. The table itself
// ═══════════════════════════════════════════════════════════════════════════

TEST(ServiceExtensions, TableNamesTheThreeIdentitiesTheEngineAlreadyOriginatesAs)
{
	// These three existed as string literals in nine places across
	// RegisterBeeper.cpp and RequestsHandler.cpp before the table did. Pinning
	// the spellings here is what makes those call sites and the guards below
	// provably the same names.
	EXPECT_TRUE(pbx::isServiceName("pbx"));
	EXPECT_TRUE(pbx::isServiceName("moh"));
	EXPECT_TRUE(pbx::isServiceName("server"));

	EXPECT_EQ(pbx::kServicePbx, "pbx");
	EXPECT_EQ(pbx::kServiceMoh, "moh");
	EXPECT_EQ(pbx::kServiceServer, "server");

	// An ordinary extension, a virtual extension and a name that is not seeded
	// yet are all NOT service names — the guards must not widen past the table.
	EXPECT_FALSE(pbx::isServiceName("101"));
	EXPECT_FALSE(pbx::isServiceName("777"));
	EXPECT_FALSE(pbx::isServiceName("voicemail"));

	// The empty string must never match the unused tail of the fixed array —
	// every guard below is handed operator input that can legitimately be empty.
	EXPECT_FALSE(pbx::isServiceName(""));
	EXPECT_EQ(pbx::serviceEndpointIndex(""), -1);
}

TEST(ServiceExtensions, NoSeededServiceIsDialableYet)
{
	// The flag, not a naming convention, is what decides whether a call may be
	// routed to a service — and no dispatch exists to answer one yet, so every
	// seed is false. If you are here because you flipped one to true: the test
	// at the bottom of this file is the one that tells you what else must land
	// first. See ServiceExtensions.hpp.
	for (std::size_t i = 0; i < pbx::kServiceEndpointCount; ++i)
	{
		EXPECT_FALSE(pbx::kServiceEndpoints[i].dialable)
			<< "service \"" << pbx::kServiceEndpoints[i].name
			<< "\" is marked dialable, but nothing answers a call routed to it";
	}
	EXPECT_FALSE(pbx::isDialableService("pbx"));
	EXPECT_FALSE(pbx::isDialableService("moh"));
	EXPECT_FALSE(pbx::isDialableService("server"));
	EXPECT_FALSE(pbx::isDialableService("101"));
}

// ═══════════════════════════════════════════════════════════════════════════
// 2. A service name is not registerable
// ═══════════════════════════════════════════════════════════════════════════

TEST(ServiceExtensions, RegisterUnderAServiceNameIsRefusedAndBindsNothing)
{
	SvcWire wire;
	RequestsHandler handler("192.168.20.1", 5060,
		[&wire](const sockaddr_in& a, std::shared_ptr<SipMessage> m) {
			wire.sent.emplace_back(a, std::move(m));
		});

	handler.handle(svcRegister("pbx", "192.168.20.66", "reg-pbx"));

	EXPECT_TRUE(wire.sawContaining("SIP/2.0 403 Reserved service extension"))
		<< "a REGISTER naming an engine identity must be refused, not bound";
	EXPECT_FALSE(wire.sawContaining("SIP/2.0 200 OK"));

	// And the refusal must have left NO binding behind. Observed the way the rest
	// of the engine would observe it: register a real phone, dial "pbx" from it,
	// and require the 404 that a name with no client gets. If the REGISTER above
	// had bound, this INVITE would instead be forwarded to 192.168.20.66.
	handler.handle(svcRegister("101", "192.168.20.11", "reg-101"));
	wire.clear();
	handler.handle(svcInvite("101", "pbx", "192.168.20.11", "call-pbx"));

	EXPECT_FALSE(wire.sawRequestTo("INVITE", "pbx"))
		<< "no INVITE may be forwarded to a service name";
	EXPECT_TRUE(wire.sawContaining("SIP/2.0 404 Not Found"));
}

TEST(ServiceExtensions, RegisterUnderAnOrdinaryExtensionStillSucceeds)
{
	// The other half of the guard: it must refuse the table's names and NOTHING
	// else. A guard that rejected every alphanumeric AOR would pass the test
	// above and break every phone.
	SvcWire wire;
	RequestsHandler handler("192.168.20.1", 5060,
		[&wire](const sockaddr_in& a, std::shared_ptr<SipMessage> m) {
			wire.sent.emplace_back(a, std::move(m));
		});

	handler.handle(svcRegister("101", "192.168.20.11", "reg-ok-101"));
	EXPECT_TRUE(wire.sawContaining("SIP/2.0 200 OK"));
	EXPECT_FALSE(wire.sawContaining("403"));

	wire.clear();
	handler.handle(svcRegister("reception", "192.168.20.12", "reg-ok-word"));
	EXPECT_TRUE(wire.sawContaining("SIP/2.0 200 OK"))
		<< "an alphanumeric AOR that is not a service name is still a legal extension";
}

// ═══════════════════════════════════════════════════════════════════════════
// 3. A service name cannot be shadowed by config
// ═══════════════════════════════════════════════════════════════════════════

TEST(ServiceExtensions, ConfigSurfacesRefuseAServiceNameAndStillAcceptOrdinaryOnes)
{
	RequestsHandler handler("192.168.21.1", 5060,
		[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});

	// Ring group: resolved BEFORE the extension lookup in onInvite, so a group
	// under a service name would shadow it outright.
	handler.setRingGroup("moh", "101,102", "ringall");
	EXPECT_FALSE(hasRingGroup(handler, "moh"));
	handler.setRingGroup("610", "101,102", "ringall");
	EXPECT_TRUE(hasRingGroup(handler, "610")) << "ordinary groups must still work";

	// Dial plan: where a catch-all pattern lives, and so where a service name is
	// most easily swallowed.
	handler.setDialRule("pbx", "group", "610");
	EXPECT_FALSE(hasDialRule(handler, "pbx"));
	handler.setDialRule("2XX", "group", "610");
	EXPECT_TRUE(hasDialRule(handler, "2XX")) << "ordinary rules must still work";

	// Call forward, SUBSCRIBER side: a service has no calls of its own to divert.
	handler.setForward("server", "always", "101");
	EXPECT_EQ(std::get<0>(forwardsOf(handler, "server")), "");

	// Call forward, TARGET side — the black hole Issue #202 was filed about.
	// Nothing validated this before: a forward to a name the engine cannot
	// deliver to was accepted, fired, and then dropped the call inside
	// redirectInvite()'s findRegistered() miss.
	handler.setForward("101", "noanswer", "moh");
	EXPECT_EQ(std::get<2>(forwardsOf(handler, "101")), "")
		<< "a forward to a service that cannot receive calls must not be stored";

	// ...and an ordinary target on the same trigger still is.
	handler.setForward("101", "noanswer", "102");
	EXPECT_EQ(std::get<2>(forwardsOf(handler, "101")), "102");
}

// ═══════════════════════════════════════════════════════════════════════════
// 4. Nothing is routed to a service that cannot answer
// ═══════════════════════════════════════════════════════════════════════════

TEST(ServiceExtensions, ARingGroupMemberNamedForAServiceIsNeverRung)
{
	// This is the guard on the `dialable` flag itself, reached through the ONE
	// choke point every routing caller uses (RequestsHandler::findRegistered).
	// A ring group's member list is free text — nothing validates members against
	// the service table — so this is the shortest path from operator input to
	// findRegistered() being asked about a service name.
	//
	// It must resolve to nothing while no dispatch exists. Marking a seed
	// `dialable = true` without building that dispatch makes findRegistered hand
	// back a peer at the SERVER'S OWN address, and this test then sees an
	// "INVITE sip:moh@192.168.22.1:5060" go out — a packet that onInvite's
	// retransmission guard drops on arrival, i.e. a call that vanishes. Breaking
	// here is the intended alarm, not a flaky assertion.
	SvcWire wire;
	RequestsHandler handler("192.168.22.1", 5060,
		[&wire](const sockaddr_in& a, std::shared_ptr<SipMessage> m) {
			wire.sent.emplace_back(a, std::move(m));
		});

	handler.handle(svcRegister("101", "192.168.22.11", "reg-g101"));
	handler.handle(svcRegister("500", "192.168.22.50", "reg-g500"));
	handler.setRingGroup("620", "101,moh", "ringall");

	wire.clear();
	handler.handle(svcInvite("500", "620", "192.168.22.50", "call-620"));

	EXPECT_TRUE(wire.sawRequestTo("INVITE", "101"))
		<< "the registered member must still be rung (the test must not pass vacuously)";
	EXPECT_FALSE(wire.sawRequestTo("INVITE", "moh"))
		<< "a non-dialable service must not be resolvable as a call target";
	// NB: "mentions the server's address" is NOT the signal to assert on here.
	// buildInviteFork legitimately stamps "To: <sip:101@<server ip:port>>" on
	// every fork, so the To header names the server on a perfectly ordinary call.
	// The REQUEST-URI is the thing that says where a packet is actually going,
	// which is what sawRequestTo matches, anchored at offset 0.
}

// ═══════════════════════════════════════════════════════════════════════════
// 5. The admin HTTP surface says no too
// ═══════════════════════════════════════════════════════════════════════════

namespace
{
	std::string svcHttpSend(int port, const std::string& method, const std::string& path,
	                        const std::string& body,
	                        const std::string& cookie, const std::string& csrf)
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
		if (connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0)
		{
#if defined(_WIN32) || defined(_WIN64)
			closesocket(s);
#else
			close(s);
#endif
			return "";
		}
		std::string req = method + " " + path + " HTTP/1.1\r\n"
			"Host: 127.0.0.1\r\n"
			"Content-Type: application/x-www-form-urlencoded\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n"
			"Cookie: " + cookie + "\r\n"
			"X-CSRF: " + csrf + "\r\n"
			"Connection: close\r\n\r\n" + body;
		send(s, req.c_str(), static_cast<int>(req.size()), 0);

		std::string resp;
		char buf[2048];
		for (;;)
		{
			int n = recv(s, buf, sizeof(buf), 0);
			if (n <= 0) break;
			resp.append(buf, static_cast<size_t>(n));
		}
#if defined(_WIN32) || defined(_WIN64)
		closesocket(s);
#else
		close(s);
#endif
		return resp;
	}

	int svcStatusOf(const std::string& resp)
	{
		size_t sp1 = resp.find(' ');
		if (sp1 == std::string::npos) return -1;
		size_t sp2 = resp.find(' ', sp1 + 1);
		if (sp2 == std::string::npos) return -1;
		return std::atoi(resp.substr(sp1 + 1, sp2 - sp1 - 1).c_str());
	}
}

// Ports: this file owns 18125-18129 (issue #213 — every HTTP test file gets
// a disjoint block; see CONTRIBUTING_FIRMWARE.md for the full table).
TEST(ServiceExtensionsHttp, EveryAdminConfigRouteRefusesAServiceName)
{
	// The dashboard's PD_RESERVED_EXT map is a courtesy; these five routes are the
	// authority, and each one is a place an operator could otherwise have claimed
	// an engine-owned name over the network.
	AdminAuth::clearCredential();

	RequestsHandler handler("192.168.23.1", 5060,
		[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});
	HttpServer server("127.0.0.1", 18125, nullptr);
	server.attachHandler(&handler);
	server.start();
	std::this_thread::sleep_for(std::chrono::milliseconds(50));

	ASSERT_TRUE(AdminAuth::setLoginCredential("admin", "realpassword123"));
	const std::string token  = AdminAuth::createSession();
	const std::string csrf   = AdminAuth::sessionCsrf(token);
	const std::string cookie = "pd_session=" + token;

	EXPECT_EQ(svcStatusOf(svcHttpSend(18125, "POST", "/api/dialplan",
		"pattern=pbx&action=group&target=610", cookie, csrf)), 400);
	EXPECT_EQ(svcStatusOf(svcHttpSend(18125, "POST", "/api/group",
		"extension=moh&members=101,102&mode=ringall", cookie, csrf)), 400);
	EXPECT_EQ(svcStatusOf(svcHttpSend(18125, "POST", "/api/dnd",
		"extension=server&on=1", cookie, csrf)), 400);
	EXPECT_EQ(svcStatusOf(svcHttpSend(18125, "POST", "/api/forward",
		"extension=pbx&trigger=always&target=101", cookie, csrf)), 400);
	EXPECT_EQ(svcStatusOf(svcHttpSend(18125, "POST", "/api/forward",
		"extension=101&trigger=noanswer&target=moh", cookie, csrf)), 400)
		<< "a forward TARGET the engine cannot deliver to must be refused too";
	EXPECT_EQ(svcStatusOf(svcHttpSend(18125, "PUT", "/api/did-mapping",
		"did=13055551234&extension=moh", cookie, csrf)), 400);

	// Not vacuous: the same routes still accept an ordinary extension.
	EXPECT_EQ(svcStatusOf(svcHttpSend(18125, "POST", "/api/dialplan",
		"pattern=4XX&action=group&target=610", cookie, csrf)), 200);
	EXPECT_EQ(svcStatusOf(svcHttpSend(18125, "POST", "/api/forward",
		"extension=101&trigger=always&target=102", cookie, csrf)), 200);

	AdminAuth::clearCredential();
}
