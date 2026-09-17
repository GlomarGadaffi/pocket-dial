// EmergencyDialing_test.cpp — 911/933 handling (Issue #166).
//
// Two things are under test and they fail in opposite directions:
//
//   1. A 911 dial must ALWAYS reach the trunk with the digits "911". The way
//      that breaks in practice is not a missing feature, it is an operator's
//      own configuration eating the call. The regression case is real and is
//      pinned below by name: a dial-plan rule with pattern "9*" and
//      stripDigits=1 -- the most natural way to write "dial 9 for an outside
//      line" -- matches "911" and rewrites it to "11".
//
//   2. When there is no trunk, the answer must be 503 and must not be 404.
//      404 means "definitive information that the user does not exist" (RFC
//      3261 21.4.5); the PBX just recognised 911, so that is a false statement
//      made to someone dialing for help. RFC 4497 8.3.1 (BCP 117) covers this
//      exact condition and says 503.
//
// Several assertions are therefore negative -- what must NOT be on the wire.
// Those are the ones that catch a regression, so they are written explicitly
// rather than left implied by a positive match.
//
// Numbers used here are 911/933 themselves plus internal extensions; no PSTN
// number appears in this file.

#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "EmergencyCall.hpp"
#include "LoopbackAnchorClient.hpp"
#include "PoolConfig.hpp"
#include "RequestsHandler.hpp"

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#else
#include <arpa/inet.h>
#endif

namespace
{
	sockaddr_in emAddr(const std::string& ip)
	{
		sockaddr_in s{};
		s.sin_family = AF_INET;
		s.sin_addr.s_addr = inet_addr(ip.c_str());
		s.sin_port = htons(5060);
		return s;
	}

	// Everything the handler put on the wire, as raw text.
	struct EmWire
	{
		std::vector<std::string> sent;

		void clear() { sent.clear(); }

		bool saw(const std::string& needle) const
		{
			for (const auto& s : sent)
			{
				if (s.find(needle) != std::string::npos) return true;
			}
			return false;
		}

		std::string dump() const
		{
			std::string out;
			for (const auto& s : sent) { out += s; out += "\n---\n"; }
			return out;
		}
	};

	std::shared_ptr<SipMessage> emRegister(const std::string& ext, const std::string& ip,
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
		return RequestsHandler::getMessageFromPool(raw, emAddr(ip));
	}

	std::shared_ptr<SipMessage> emInviteWithBody(const std::string& fromExt,
		const std::string& toExt, const std::string& ip, const std::string& callId,
		const std::string& body)
	{
		std::string raw =
			"INVITE sip:" + toExt + "@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + ip + ":5060;branch=z9hG4bKi" + callId + "\r\n"
			"From: <sip:" + fromExt + "@server>;tag=ft" + callId + "\r\n"
			"To: <sip:" + toExt + "@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Max-Forwards: 70\r\n"
			"Contact: <sip:" + fromExt + "@" + ip + ":5060>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		return RequestsHandler::getMessageFromPool(raw, emAddr(ip));
	}

	std::shared_ptr<SipMessage> emInvite(const std::string& fromExt, const std::string& toExt,
		const std::string& ip, const std::string& callId)
	{
		std::string body =
			"v=0\r\n"
			"o=- 0 0 IN IP4 " + ip + "\r\n"
			"s=-\r\n"
			"c=IN IP4 " + ip + "\r\n"
			"t=0 0\r\n"
			"m=audio 10000 RTP/AVP 0\r\n"
			"a=rtpmap:0 PCMU/8000\r\n";
		return emInviteWithBody(fromExt, toExt, ip, callId, body);
	}

	// Issue #314: PCMA only, no PCMU line at all -- the exact offer #311's codec
	// gate rejects on every server-terminated leg, originateAnchorCall's included.
	std::shared_ptr<SipMessage> emInvitePcma(const std::string& fromExt, const std::string& toExt,
		const std::string& ip, const std::string& callId)
	{
		std::string body =
			"v=0\r\n"
			"o=- 0 0 IN IP4 " + ip + "\r\n"
			"s=-\r\n"
			"c=IN IP4 " + ip + "\r\n"
			"t=0 0\r\n"
			"m=audio 10000 RTP/AVP 8\r\n"
			"a=rtpmap:8 PCMA/8000\r\n";
		return emInviteWithBody(fromExt, toExt, ip, callId, body);
	}

	// A handler with ext 101 registered and the wire captured.
	struct Bench
	{
		EmWire wire;
		std::unique_ptr<RequestsHandler> handler;

		Bench()
		{
			handler = std::make_unique<RequestsHandler>("192.168.77.1", 5060,
				[this](const sockaddr_in&, std::shared_ptr<SipMessage> m) {
					wire.sent.push_back(m->toString());
				});
			handler->handle(emRegister("101", "192.168.77.11", "em-reg-101"));
			wire.clear();
		}

		LoopbackAnchorClient* loopback()
		{
			return dynamic_cast<LoopbackAnchorClient*>(handler->anchorClientForTest());
		}
	};
}

// ─────────────────────────────────────────────────────────────────────────────
// The pure classifier
// ─────────────────────────────────────────────────────────────────────────────

TEST(EmergencyClassify, RecognisesTheEmergencyNumberAndItsTestNumber)
{
	const auto live = pbx::classifyEmergencyDial("911");
	EXPECT_TRUE(live.isEmergency);
	EXPECT_FALSE(live.isTest);
	EXPECT_EQ(live.number, "911");

	const auto test = pbx::classifyEmergencyDial("933");
	EXPECT_TRUE(test.isEmergency);
	EXPECT_TRUE(test.isTest) << "933 must be distinguishable so a test is never logged as a live emergency";
	EXPECT_EQ(test.number, "933");
}

TEST(EmergencyClassify, AbsorbsOneTrunkAccessDigitButAlwaysYieldsTheBareNumber)
{
	const auto prefixed = pbx::classifyEmergencyDial("9911");
	EXPECT_TRUE(prefixed.isEmergency);
	EXPECT_TRUE(prefixed.hadTrunkPrefix);
	EXPECT_EQ(prefixed.number, "911") << "the trunk must be handed 911, never 9911";

	const auto prefixedTest = pbx::classifyEmergencyDial("9933");
	EXPECT_TRUE(prefixedTest.isEmergency);
	EXPECT_TRUE(prefixedTest.isTest);
	EXPECT_EQ(prefixedTest.number, "933");
}

TEST(EmergencyClassify, DoesNotFireOnOrdinaryNumbersThatMerelyContain911)
{
	// A wrong POSITIVE hijacks an ordinary call onto the emergency path, so the
	// match is exact against a closed set and nothing else.
	for (const char* n : {"9110", "1911", "99911", "91", "9", "", "119",
	                      "911911", "5559110", "933x", "89911"})
	{
		EXPECT_FALSE(pbx::classifyEmergencyDial(n).isEmergency)
			<< "must not classify \"" << n << "\" as an emergency call";
	}
}

TEST(EmergencyClassify, DoesNotStripATrunkDigitWhenTheRemainderIsNotAnEmergencyNumber)
{
	// "9411" is a 9-prefixed ordinary dial, not 411 emergency (411 is not one).
	const auto d = pbx::classifyEmergencyDial("9411");
	EXPECT_FALSE(d.isEmergency);
	EXPECT_FALSE(d.hadTrunkPrefix);
}

// ─────────────────────────────────────────────────────────────────────────────
// Routing: the call must reach the trunk, whatever the operator configured
// ─────────────────────────────────────────────────────────────────────────────

TEST(EmergencyDialing, DialingNineOneOneReachesTheTrunkWithTheBareNumber)
{
	Bench b;
	ASSERT_NE(b.loopback(), nullptr) << "host build should boot the loopback anchor";
	ASSERT_TRUE(b.loopback()->isConnected());

	b.handler->handle(emInvite("101", "911", "192.168.77.11", "em-911-ok"));

	EXPECT_EQ(b.loopback()->lastMakeCallDestination(), "911")
		<< "the anchor must be asked to dial exactly 911";
}

TEST(EmergencyDialing, DialingNineNineOneOneStillReachesTheTrunkAsNineOneOne)
{
	Bench b;
	ASSERT_NE(b.loopback(), nullptr);

	b.handler->handle(emInvite("101", "9911", "192.168.77.11", "em-9911"));

	const std::string dest = b.loopback()->lastMakeCallDestination();
	EXPECT_EQ(dest, "911");
	EXPECT_NE(dest, "11")   << "stripping the trunk digit must not leave 11";
	EXPECT_NE(dest, "9911") << "the prefixed form must not be dialed verbatim";
}

TEST(EmergencyDialing, AnOutsideLineRuleCannotRewriteNineOneOneIntoEleven)
{
	// THE regression test. Before #166, this exact configuration -- the most
	// natural way to express "dial 9 for an outside line" -- silently turned a
	// dialed 911 into 11, because dialPatternMatches() treats a trailing '*' as
	// "absorb the rest" and applyTrunkTransform() then strips the leading digit.
	// The emergency intercept now runs before the dial plan, so the rule cannot
	// see 911 at all.
	Bench b;
	ASSERT_NE(b.loopback(), nullptr);

	b.handler->setDialRule("9*", "trunk", "", 1);

	b.handler->handle(emInvite("101", "911", "192.168.77.11", "em-911-rule"));

	const std::string dest = b.loopback()->lastMakeCallDestination();
	EXPECT_EQ(dest, "911")
		<< "a \"9*\" strip-1 outside-line rule must never capture 911";
	EXPECT_NE(dest, "11")
		<< "this is the exact live defect #166 closes: 911 rewritten to 11";
}

TEST(EmergencyDialing, ACatchAllDialRuleCannotSwallowNineOneOne)
{
	Bench b;
	ASSERT_NE(b.loopback(), nullptr);

	// A catch-all pointing somewhere that is not the trunk at all.
	b.handler->setDialRule("*", "group", "600", 0);

	b.handler->handle(emInvite("101", "911", "192.168.77.11", "em-911-catchall"));

	EXPECT_EQ(b.loopback()->lastMakeCallDestination(), "911")
		<< "a catch-all rule must not intercept an emergency call";
}

TEST(EmergencyDialing, SecureModeDoesNotChallengeAnEmergencyCall)
{
	// Secure mode is call-setup POLICY. It may not stand between a registered
	// phone and 911. (Registration itself still applies -- that is a capability
	// gate, not policy; see EmergencyCall.hpp.)
	Bench b;
	ASSERT_NE(b.loopback(), nullptr);
	b.handler->setRegistrarMode(RequestsHandler::RegistrarMode::Secure);
	b.wire.clear();

	b.handler->handle(emInvite("101", "911", "192.168.77.11", "em-911-secure"));

	EXPECT_FALSE(b.wire.saw("SIP/2.0 401"))
		<< "911 must not be challenged in secure mode, got:\n" << b.wire.dump();
	EXPECT_EQ(b.loopback()->lastMakeCallDestination(), "911");
}

TEST(EmergencyDialing, TheTestNumberRoutesJustLikeTheLiveOne)
{
	Bench b;
	ASSERT_NE(b.loopback(), nullptr);

	b.handler->handle(emInvite("101", "933", "192.168.77.11", "em-933"));

	EXPECT_EQ(b.loopback()->lastMakeCallDestination(), "933")
		<< "933 is a real outbound call to the carrier's E911 test service";
}

// ─────────────────────────────────────────────────────────────────────────────
// No trunk: 503, and specifically not 404
// ─────────────────────────────────────────────────────────────────────────────

TEST(EmergencyDialing, WithNoTrunkConnectedTheAnswerIsFiveOhThreeAndNeverFourOhFour)
{
	Bench b;
	ASSERT_NE(b.loopback(), nullptr);
	b.handler->anchorClientForTest()->stop();   // no trunk reachable
	ASSERT_FALSE(b.handler->anchorClientForTest()->isConnected());
	b.wire.clear();

	b.handler->handle(emInvite("101", "911", "192.168.77.11", "em-911-notrunk"));

	EXPECT_TRUE(b.wire.saw("SIP/2.0 503"))
		<< "RFC 4497 8.3.1: no available channel is 503. Got:\n" << b.wire.dump();

	// The negative assertions are the point of this test.
	EXPECT_FALSE(b.wire.saw("404 Not Found"))
		<< "404 asserts the number does not exist -- a falsehood about 911";
	EXPECT_FALSE(b.wire.saw("480 Temporarily Unavailable"))
		<< "480 is a callee-side condition (RFC 3398 7.2.4.1 maps 19/20/31), not a trunk outage";
	EXPECT_FALSE(b.wire.saw("SIP/2.0 6"))
		<< "a 6xx is globally final and would foreclose any alternate route upstream";
}

TEST(EmergencyDialing, TheFiveOhThreeCarriesAWarningAndNoRetryAfter)
{
	Bench b;
	b.handler->anchorClientForTest()->stop();
	b.wire.clear();

	b.handler->handle(emInvite("101", "911", "192.168.77.11", "em-911-warn"));

	EXPECT_TRUE(b.wire.saw("Warning: 399"))
		<< "399 is the only warn-code that fits; there is no emergency-specific one";
	EXPECT_TRUE(b.wire.saw("Emergency call could not be routed"))
		<< "the reason must say what actually happened, since handsets display it";

	// RFC 3261 21.5.4: a UA SHOULD NOT send further requests to a server for the
	// Retry-After duration. Backing a handset off the PBX after a failed 911
	// attempt is the last thing anyone wants.
	EXPECT_FALSE(b.wire.saw("Retry-After"))
		<< "a 911 failure must never tell the handset to back off:\n" << b.wire.dump();
}

TEST(EmergencyDialing, ANineOneOneDialIsNeverAnsweredTwice)
{
	// originateAnchorCall is called with respondIfDisconnected=false precisely so
	// it stays silent and this path owns the response. If that contract slips,
	// the handset gets two final responses to one INVITE.
	Bench b;
	b.handler->anchorClientForTest()->stop();
	b.wire.clear();

	b.handler->handle(emInvite("101", "911", "192.168.77.11", "em-911-once"));

	int finals = 0;
	for (const auto& s : b.wire.sent)
	{
		if (s.rfind("SIP/2.0 4", 0) == 0 || s.rfind("SIP/2.0 5", 0) == 0 ||
		    s.rfind("SIP/2.0 6", 0) == 0 || s.rfind("SIP/2.0 2", 0) == 0)
		{
			++finals;
		}
	}
	EXPECT_EQ(finals, 1) << "exactly one final response, got " << finals << ":\n" << b.wire.dump();
}

// ─────────────────────────────────────────────────────────────────────────────
// PCMA-only offer: 503, and specifically not #311's generic 488 (Issue #314)
// ─────────────────────────────────────────────────────────────────────────────

TEST(EmergencyDialing, PcmaOnlyOfferGetsThePurposeBuiltFiveOhThreeNotTheGenericFourEightEight)
{
	Bench b;
	ASSERT_NE(b.loopback(), nullptr);
	ASSERT_TRUE(b.loopback()->isConnected())
		<< "the trunk must be UP for this test -- a disconnected trunk hits the "
		<< "\"no trunk\" path above for an unrelated reason";

	b.handler->handle(emInvitePcma("101", "911", "192.168.77.11", "em-911-pcma"));

	EXPECT_TRUE(b.wire.saw("SIP/2.0 503"))
		<< "a codec-rejected 911 offer must still get 911's own 503, not 488:\n" << b.wire.dump();
	EXPECT_FALSE(b.wire.saw("488 Not Acceptable Here"))
		<< "originateAnchorCall's generic codec-gate response must not reach a 911 caller:\n"
		<< b.wire.dump();
	EXPECT_TRUE(b.wire.saw("Emergency call could not be routed"))
		<< "same purpose-built reason phrase as the no-trunk case:\n" << b.wire.dump();
	EXPECT_TRUE(b.wire.saw("no G.711 codec offered"))
		<< "the Warning text must say what actually went wrong, not claim a trunk outage:\n"
		<< b.wire.dump();
	EXPECT_FALSE(b.wire.saw("no outbound trunk connected"))
		<< "the trunk IS connected in this test -- that Warning text would be false:\n"
		<< b.wire.dump();
	EXPECT_EQ(b.loopback()->lastMakeCallDestination(), "")
		<< "a codec-rejected offer must never reach makeCall()";
}

TEST(EmergencyDialing, PcmaOnlyNineOneOneIsNeverAnsweredTwice)
{
	// Guards the #314 fix's own hazard: routeEmergencyCall must build its 503
	// only because originateAnchorCall's codec gate stayed silent (codecRejectedOut
	// requested) -- if that contract slips, the handset gets both the gate's 488
	// AND this function's 503 for one INVITE.
	Bench b;
	ASSERT_TRUE(b.loopback()->isConnected());

	b.handler->handle(emInvitePcma("101", "911", "192.168.77.11", "em-911-pcma-once"));

	int finals = 0;
	for (const auto& s : b.wire.sent)
	{
		if (s.rfind("SIP/2.0 4", 0) == 0 || s.rfind("SIP/2.0 5", 0) == 0 ||
		    s.rfind("SIP/2.0 6", 0) == 0 || s.rfind("SIP/2.0 2", 0) == 0)
		{
			++finals;
		}
	}
	EXPECT_EQ(finals, 1) << "exactly one final response, got " << finals << ":\n" << b.wire.dump();
}

TEST(EmergencyDialing, OrdinaryTrunkCallsStillGetTheGenericFourEightEightForPcmaOnly)
{
	// #314 must not weaken originateAnchorCall's own codec gate for its other
	// callers -- only routeEmergencyCall opts into the silent/substitute path.
	// A plain 555 dial (onAnchorInvite, same function, codecRejectedOut=nullptr)
	// must still get the original 488 unchanged.
	Bench b;
	ASSERT_TRUE(b.loopback()->isConnected());

	b.handler->handle(emInvitePcma("101", "555", "192.168.77.11", "em-555-pcma"));

	EXPECT_TRUE(b.wire.saw("488 Not Acceptable Here"))
		<< "a non-emergency PCMA-only offer must keep #311's original behaviour:\n"
		<< b.wire.dump();
	EXPECT_FALSE(b.wire.saw("SIP/2.0 503"))
		<< "555 has no purpose-built substitute response -- it must not gain one:\n"
		<< b.wire.dump();
}

// ─────────────────────────────────────────────────────────────────────────────
// Config hardening: nothing an operator types may claim 911
// ─────────────────────────────────────────────────────────────────────────────

TEST(EmergencyDialing, ARingGroupCannotBeNamedForAnEmergencyNumber)
{
	// findRingGroup() runs before the dial plan in onInvite, so a group named
	// 911 would have shadowed emergency dialing outright. It is refused at
	// config time rather than persisted as config that silently never fires.
	Bench b;

	b.handler->setRingGroup("911", "101", "ringall");
	b.handler->setRingGroup("933", "101", "ringall");

	for (const auto& g : b.handler->getRingGroups())
	{
		EXPECT_NE(std::get<0>(g), "911") << "a ring group named 911 must be refused";
		EXPECT_NE(std::get<0>(g), "933") << "a ring group named 933 must be refused";
	}
}

TEST(EmergencyDialing, ReservedExtensionRefusalIsNowOneSharedListNotThreeDrifted)
{
	// Before #166 the three validators in PbxFeatureConfig.cpp carried three
	// DIFFERENT hand-copied lists: ring groups and forwards omitted 440, the
	// dial-plan validator omitted 888, and none of them covered 911/933.
	Bench b;

	for (const char* ext : {"777", "999", "888", "555", "440", "911", "933"})
	{
		b.handler->setRingGroup(ext, "101", "ringall");
		b.handler->setDialRule(ext, "group", "600", 0);
	}

	for (const auto& g : b.handler->getRingGroups())
	{
		EXPECT_FALSE(pbx::isReservedExtension(std::get<0>(g)))
			<< "reserved extension accepted as a ring group: " << std::get<0>(g);
	}
	for (const auto& r : b.handler->getDialRules())
	{
		EXPECT_FALSE(pbx::isReservedExtension(std::get<0>(r)))
			<< "reserved extension accepted as a dial-rule pattern: " << std::get<0>(r);
	}
}
