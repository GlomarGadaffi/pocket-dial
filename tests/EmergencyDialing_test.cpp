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
			// Issue #521: the loopback anchor refuses every emergency number
			// (EmergencyRoute_test.cpp pins that). These tests are about how a
			// provider is asked to dial, so it stands in for a real one here.
			handler->setAnchorPlacesRealCallsForTest(true);
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

TEST(EmergencyDialing, ANineOneOneFromAnotherAddressIsNotRefusedByTheCallerBinding)
{
	// #497 refuses a call whose source is not the caller's registered address.
	// 911 is never gated (#454): the check sits after the emergency branch, so a
	// 911 naming ext 101 from a different host still reaches the trunk.
	Bench b;
	ASSERT_NE(b.loopback(), nullptr);
	ASSERT_TRUE(b.loopback()->isConnected());

	b.handler->handle(emInvite("101", "911", "192.168.77.99", "em-911-unbound"));

	EXPECT_EQ(b.loopback()->lastMakeCallDestination(), "911")
		<< "the caller binding must not block an emergency call";
	EXPECT_FALSE(b.wire.saw("Caller Not Registered From This Address"));
}

TEST(EmergencyDialing, ASecuredCallerInLearnModeReachesNineOneOneWithoutCredentials)
{
	// #505 challenges INVITEs from Secured devices in Learn mode. 911 is never
	// gated (#454): the emergency branch runs before that challenge, so a Secured
	// phone with no (or expired) credentials still reaches the trunk.
	Bench b;
	ASSERT_NE(b.loopback(), nullptr);
	ASSERT_TRUE(b.loopback()->isConnected());
	b.handler->setRegistrarMode(RequestsHandler::RegistrarMode::Learn);
	b.handler->adoptDeviceForTest("0200000000cc", "101", Registrar::DeviceState::Secured);

	b.handler->handle(emInvite("101", "911", "192.168.77.11", "em-911-secured"));

	EXPECT_EQ(b.loopback()->lastMakeCallDestination(), "911")
		<< "a Secured caller without credentials must still reach 911";
	EXPECT_FALSE(b.wire.saw("SIP/2.0 401"));
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

// ─────────────────────────────────────────────────────────────────────────────
// #834 (desmo: "YES, same as dialed"): a 911 that a dial-plan rule produces
// gets every exemption a dialed 911 gets, and an ordinary rule number none
// ─────────────────────────────────────────────────────────────────────────────

namespace
{
	std::string emOffer(const std::string& ip)
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

	// 101's INVITE to `to` from `ip`, with `extra` header lines and, when
	// `multipart`, the offer beside a PIDF-LO location (RFC 6442's shape).
	std::shared_ptr<SipMessage> emShapedInvite(const std::string& to, const std::string& ip,
		const std::string& callId, const std::string& extra, bool multipart)
	{
		const std::string body = !multipart ? emOffer(ip) :
			"--loc\r\nContent-Type: application/sdp\r\n\r\n" + emOffer(ip) +
			"--loc\r\nContent-Type: application/pidf+xml\r\n\r\n"
			"<presence xmlns=\"urn:ietf:params:xml:ns:pidf\" entity=\"pres:101@pd.example\"/>\r\n"
			"--loc--\r\n";
		std::string raw =
			"INVITE sip:" + to + "@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + ip + ":5060;branch=z9hG4bKs" + callId + "\r\n"
			"From: <sip:101@server>;tag=fs" + callId + "\r\n"
			"To: <sip:" + to + "@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Max-Forwards: 70\r\n"
			"Contact: <sip:101@" + ip + ":5060>\r\n" + extra +
			"Content-Type: " + std::string(multipart ? "multipart/mixed;boundary=loc" : "application/sdp") + "\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		return RequestsHandler::getMessageFromPool(raw, emAddr(ip));
	}
}

TEST(EmergencyDialing, ARuleProducedNineOneOneGetsEveryExemptionADialedOneGets)
{
	struct Shape
	{
		const char* what;
		int policy;               // 1: Secure registrar mode; 2: Learn mode, 101 adopted as Secured (#505)
		const char* ip;           // 101 registered from .11
		const char* extra;
		bool multipart;
		const char* refusal;      // what an ordinary rule number still gets
	};
	const Shape shapes[] = {
		{"secure mode, no credential",         1, "192.168.77.11", "",                       false, "SIP/2.0 403 Extension Not Provisioned"},
		{"a Secured device in Learn mode",     2, "192.168.77.11", "",                       false, "SIP/2.0 403 Extension Not Provisioned"},
		{"an address #497 refuses",            0, "192.168.77.99", "",                       false, "Caller Not Registered From This Address"},
		{"a Session-Expires under the floor",  0, "192.168.77.11", "Session-Expires: 30\r\n", false, "SIP/2.0 422"},
		{"a multipart body with a PIDF-LO",    0, "192.168.77.11", "",                       true,  "SIP/2.0 415"},
	};
	{
		// Control: with none of the shapes, the ordinary rule reaches the provider.
		Bench b;
		b.handler->setDialRule("45X", "trunk", "", 0);
		b.handler->handle(emShapedInvite("455", "192.168.77.11", "em-834-control", "", false));
		ASSERT_EQ(b.loopback()->lastMakeCallDestination(), "455") << b.wire.dump();
	}
	auto applyPolicy = [](Bench& b, int policy) {
		if (policy == 1) b.handler->setRegistrarMode(RequestsHandler::RegistrarMode::Secure);
		if (policy == 2)
		{
			b.handler->setRegistrarMode(RequestsHandler::RegistrarMode::Learn);
			b.handler->adoptDeviceForTest("0200000000cc", "101", Registrar::DeviceState::Secured);
		}
	};
	int n = 0;
	for (const Shape& s : shapes)
	{
		SCOPED_TRACE(s.what);
		++n;
		{
			Bench b;
			applyPolicy(b, s.policy);
			b.handler->setDialRule("0", "trunk", "911", 1);
			b.wire.clear();
			b.handler->handle(emShapedInvite("0", s.ip, "em-834-911-" + std::to_string(n), s.extra, s.multipart));
			EXPECT_EQ(b.loopback()->lastMakeCallDestination(), "911")
				<< "a rule-produced 911 must reach the provider as a dialed one does:\n" << b.wire.dump();
			EXPECT_FALSE(b.wire.saw("SIP/2.0 4")) << b.wire.dump();
		}
		{
			// Negative: an ordinary rule number keeps the check.
			Bench b;
			applyPolicy(b, s.policy);
			b.handler->setDialRule("45X", "trunk", "", 0);
			b.wire.clear();
			b.handler->handle(emShapedInvite("455", s.ip, "em-834-rule-" + std::to_string(n), s.extra, s.multipart));
			EXPECT_TRUE(b.wire.saw(s.refusal)) << b.wire.dump();
			EXPECT_EQ(b.loopback()->lastMakeCallDestination(), "") << "the ordinary rule never fired";
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// #877 review S-A4: dialRuleMakesEmergency() now decides routing, so its
// precedence mirror is pinned. onInvite routes a configured ring group, a park
// orbit, a configured page zone and the pickup codes before the dial plan, so a
// rule that would make 911 of their number never fires for them. Those cases
// are characterization tests: they pass before and after the fix, and a slip
// in the mirror turns them red. A registered extension's number is not made a
// 911 by a wildcard rule either (desmo, #877: "Only wildcard rules yield").
// Before that decision the rule did capture it, as on main: #69 puts the dial
// plan before the extension lookup, and #538 M2 routed the result as 911.
// ─────────────────────────────────────────────────────────────────────────────

TEST(EmergencyDialing, ARuleThatMakesNineOneOneNeverCapturesWhatOnInviteRoutesFirst)
{
	struct Case
	{
		const char* what;
		const char* pattern;
		int strip;
		const char* shadowed;   // routed before the dial plan: never a 911
		const char* control;    // the same rule's 911, or "" when the rule has no other number
	};
	const Case cases[] = {
		{"a configured ring group",  "6XX",   3, "600",   "601"},
		{"a park orbit",             "7XX",   3, "700",   "750"},
		{"a configured page zone",   "98X",   3, "980",   "981"},   // 981 is not configured
		{"the group pickup code",    "*8",    2, "*8",    ""},
		{"a directed pickup code",   "**1XX", 5, "**102", ""},
	};
	int n = 0;
	for (const Case& c : cases)
	{
		SCOPED_TRACE(c.what);
		++n;
		{
			Bench b;
			b.handler->handle(emRegister("102", "192.168.77.12", "em-reg-102"));
			b.handler->setRingGroup("600", "102", "ringall");
			b.handler->setPageZone("980", "102");
			b.handler->setDialRule(c.pattern, "trunk", "911", c.strip);
			ASSERT_EQ(b.handler->getDialRules().size(), 1u) << "precondition: the rule is stored";
			b.wire.clear();
			b.handler->handle(emInvite("101", c.shadowed, "192.168.77.11", "em-s-a4-" + std::to_string(n)));
			EXPECT_EQ(b.loopback()->lastMakeCallDestination(), "")
				<< c.shadowed << " is routed before the dial plan; the rule must not make it a 911:\n" << b.wire.dump();
			EXPECT_FALSE(b.wire.saw("Emergency Call Not Routable")) << b.wire.dump();
		}
		if (c.control[0] != '\0')
		{
			// Control: the same rule does make a 911 of a number it is not shadowed for.
			Bench b;
			b.handler->setRingGroup("600", "102", "ringall");
			b.handler->setPageZone("980", "102");
			b.handler->setDialRule(c.pattern, "trunk", "911", c.strip);
			b.handler->handle(emInvite("101", c.control, "192.168.77.11", "em-s-a4-ctl-" + std::to_string(n)));
			EXPECT_EQ(b.loopback()->lastMakeCallDestination(), "911") << b.wire.dump();
		}
	}
	{
		SCOPED_TRACE("a registered extension: a wildcard rule yields to it (desmo, #877)");
		Bench b;
		b.handler->handle(emRegister("102", "192.168.77.12", "em-reg-102"));
		b.handler->setDialRule("1XX", "trunk", "911", 3);
		b.wire.clear();
		b.handler->handle(emInvite("101", "102", "192.168.77.11", "em-s-a4-ext"));
		EXPECT_EQ(b.loopback()->lastMakeCallDestination(), "")
			<< "102 is a registered extension; the wildcard rule must not make it a 911:\n" << b.wire.dump();
		EXPECT_TRUE(b.wire.saw("INVITE sip:102@")) << "102 rings:\n" << b.wire.dump();
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// desmo, #877: "Only wildcard rules yield". A WILDCARD dial-plan rule ('X', or a
// trailing '*') whose transform makes a number 911/933 steps aside for a
// REGISTERED extension, as if the rule did not exist. A LITERAL rule (0 -> 911,
// 112 -> 911) always fires, so a phone that registers its number in Learn mode
// cannot take the operator's emergency rule over. Every other rule keeps #69's
// order, and a dialed 911/933 never reaches the dial plan.
// ─────────────────────────────────────────────────────────────────────────────

TEST(EmergencyDialing, OnlyAWildcardRuleThatMakesNineOneOneYieldsToARegisteredExtension)
{
	{
		SCOPED_TRACE("control: the wildcard rule still makes 911 of a number in its range that is not registered");
		Bench b;
		b.handler->handle(emRegister("102", "192.168.77.12", "em-reg-102"));
		b.handler->setDialRule("1XX", "trunk", "911", 3);
		b.wire.clear();
		b.handler->handle(emInvite("101", "199", "192.168.77.11", "em-877-199"));
		EXPECT_EQ(b.loopback()->lastMakeCallDestination(), "911") << b.wire.dump();
	}
	struct Rogue { const char* number; int strip; };
	for (const Rogue& r : {Rogue{"0", 1}, Rogue{"112", 3}})
	{
		SCOPED_TRACE(std::string("a literal rule ") + r.number + " -> 911 fires although a phone registered " + r.number);
		Bench b;
		b.handler->handle(emRegister(r.number, "192.168.77.13", std::string("em-reg-rogue-") + r.number));
		ASSERT_TRUE(b.wire.saw("SIP/2.0 200 OK")) << "precondition: " << r.number << " registered:\n" << b.wire.dump();
		b.handler->setDialRule(r.number, "trunk", "911", r.strip);
		ASSERT_EQ(b.handler->getDialRules().size(), 1u) << "precondition: the rule is stored";
		b.wire.clear();
		b.handler->handle(emInvite("101", r.number, "192.168.77.11", std::string("em-877-rogue-") + r.number));
		EXPECT_EQ(b.loopback()->lastMakeCallDestination(), "911")
			<< "the operator's literal emergency rule must not yield to a registration:\n" << b.wire.dump();
		EXPECT_FALSE(b.wire.saw(std::string("INVITE sip:") + r.number + "@")) << b.wire.dump();
	}
	{
		SCOPED_TRACE("an ordinary rule still captures an extension's number (#69 order unchanged)");
		Bench b;
		b.handler->handle(emRegister("102", "192.168.77.12", "em-reg-102"));
		b.handler->setDialRule("1XX", "trunk", "", 0);
		b.wire.clear();
		b.handler->handle(emInvite("101", "102", "192.168.77.11", "em-877-ordinary"));
		EXPECT_EQ(b.loopback()->lastMakeCallDestination(), "102") << b.wire.dump();
		EXPECT_FALSE(b.wire.saw("INVITE sip:102@")) << b.wire.dump();
	}
	{
		SCOPED_TRACE("as if the wildcard 911 rule did not exist: a later ordinary rule still applies");
		Bench b;
		b.handler->handle(emRegister("102", "192.168.77.12", "em-reg-102"));
		b.handler->setDialRule("1XX", "trunk", "911", 3);
		b.handler->setDialRule("10X", "trunk", "", 0);
		ASSERT_EQ(b.handler->getDialRules().size(), 2u) << "precondition: both rules are stored";
		b.wire.clear();
		b.handler->handle(emInvite("101", "102", "192.168.77.11", "em-877-later"));
		EXPECT_EQ(b.loopback()->lastMakeCallDestination(), "102") << b.wire.dump();
	}
	{
		SCOPED_TRACE("the known limit: an extension the registrar knows but that is not registered is not protected");
		Bench b;
		b.handler->adoptDeviceForTest("0200000000dd", "103");
		b.handler->setDialRule("1XX", "trunk", "911", 3);
		b.wire.clear();
		b.handler->handle(emInvite("101", "103", "192.168.77.11", "em-877-offline"));
		EXPECT_EQ(b.loopback()->lastMakeCallDestination(), "911")
			<< "the test is registration, as for a call no rule matches:\n" << b.wire.dump();
	}
}

// The mirror (dialRuleMakesEmergency(), which the #759 gate and the #760 unwrap
// ask) agrees with the router: a wildcard rule's 911 for registered 102 is no
// 911 to either, so the gate refuses what it refuses on any call to 102; the
// same rule's 911 for 199, and a literal rule's 911 for a registered 112, are
// 911s to both, so the gate yields.
TEST(EmergencyDialing, TheHeaderGateAgreesWithTheRouterOnWhichRuleNumbersAreNineOneOne)
{
	struct Shape { const char* what; const char* extra; bool multipart; const char* refusal; };
	int n = 0;
	for (const Shape& s : {Shape{"Require: 100rel", "Require: 100rel\r\n", false, "SIP/2.0 420"},
	                       Shape{"a multipart body with a PIDF-LO", "", true, "SIP/2.0 415"}})
	{
		SCOPED_TRACE(s.what);
		++n;
		{
			Bench b;
			b.handler->handle(emRegister("102", "192.168.77.12", "em-reg-102"));
			b.handler->setDialRule("1XX", "trunk", "911", 3);
			b.wire.clear();
			b.handler->handle(emShapedInvite("102", "192.168.77.11", "em-877-gate-102-" + std::to_string(n), s.extra, s.multipart));
			EXPECT_TRUE(b.wire.saw(s.refusal)) << "102 is not a 911, so the gate does not yield:\n" << b.wire.dump();
			EXPECT_EQ(b.loopback()->lastMakeCallDestination(), "") << b.wire.dump();
		}
		{
			Bench b;
			b.handler->handle(emRegister("102", "192.168.77.12", "em-reg-102"));
			b.handler->setDialRule("1XX", "trunk", "911", 3);
			b.wire.clear();
			b.handler->handle(emShapedInvite("199", "192.168.77.11", "em-877-gate-199-" + std::to_string(n), s.extra, s.multipart));
			EXPECT_EQ(b.loopback()->lastMakeCallDestination(), "911") << b.wire.dump();
			EXPECT_FALSE(b.wire.saw("SIP/2.0 4")) << b.wire.dump();
		}
		{
			Bench b;
			b.handler->handle(emRegister("112", "192.168.77.13", "em-reg-rogue-112"));
			ASSERT_TRUE(b.wire.saw("SIP/2.0 200 OK")) << "precondition: 112 registered:\n" << b.wire.dump();
			b.handler->setDialRule("112", "trunk", "911", 3);
			b.wire.clear();
			b.handler->handle(emShapedInvite("112", "192.168.77.11", "em-877-gate-112-" + std::to_string(n), s.extra, s.multipart));
			EXPECT_EQ(b.loopback()->lastMakeCallDestination(), "911") << b.wire.dump();
			EXPECT_FALSE(b.wire.saw("SIP/2.0 4")) << b.wire.dump();
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// #877 follow-up (S1): one INVITE, one registration snapshot. The admission
// gates ask dialRuleMakesEmergency(), which reads registration (a wildcard 911
// rule yields to a registered extension), and onInvite() asks it again. The
// client sweep ran between the two, so a lease that lapsed and was swept in the
// same pass made the gate judge 102 an extension and refuse a call onInvite
// would have routed to 911.
// ─────────────────────────────────────────────────────────────────────────────

TEST(EmergencyDialing, OneInviteIsJudgedAgainstOneRegistrationSnapshot)
{
	struct Shape { const char* what; const char* extra; bool multipart; const char* refusal; };
	int n = 0;
	for (const Shape& s : {Shape{"Require: 100rel", "Require: 100rel\r\n", false, "SIP/2.0 420"},
	                       Shape{"a multipart body with a PIDF-LO", "", true, "SIP/2.0 415"}})
	{
		SCOPED_TRACE(s.what);
		++n;
		{
			SCOPED_TRACE("102's lease lapsed, and this INVITE's pass sweeps it");
			Bench b;
			b.handler->handle(emRegister("102", "192.168.77.12", "em-reg-102"));
			b.handler->setDialRule("1XX", "trunk", "911", 3);
			b.handler->expireLeaseForNextSweepForTest("102");
			b.wire.clear();
			b.handler->handle(emShapedInvite("102", "192.168.77.11", "em-s1-lapsed-" + std::to_string(n), s.extra, s.multipart));
			EXPECT_EQ(b.loopback()->lastMakeCallDestination(), "911")
				<< "102 is no longer registered, so the rule makes this a 911, for the gate as for onInvite:\n" << b.wire.dump();
			EXPECT_FALSE(b.wire.saw(s.refusal)) << b.wire.dump();
		}
		{
			SCOPED_TRACE("control: 102 is still registered, so both reads see an extension");
			Bench b;
			b.handler->handle(emRegister("102", "192.168.77.12", "em-reg-102"));
			b.handler->setDialRule("1XX", "trunk", "911", 3);
			b.wire.clear();
			b.handler->handle(emShapedInvite("102", "192.168.77.11", "em-s1-live-" + std::to_string(n), s.extra, s.multipart));
			EXPECT_TRUE(b.wire.saw(s.refusal)) << b.wire.dump();
			EXPECT_EQ(b.loopback()->lastMakeCallDestination(), "") << b.wire.dump();
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// #877 follow-up: the wildcard yield's remaining edges (desmo: "Only wildcard
// rules yield"). A registered extension under a wildcard 911/933 rule is an
// ordinary call with every ordinary check; the rule's 911/933 for any other
// number is an emergency call with every emergency exemption.
// ─────────────────────────────────────────────────────────────────────────────

namespace
{
	// 101's INVITE to `to` with a second active audio stream, which #199's
	// stream cap refuses on an ordinary call.
	std::shared_ptr<SipMessage> emTwoStreamInvite(const std::string& to, const std::string& callId)
	{
		const std::string ip = "192.168.77.11";
		return emInviteWithBody("101", to, ip, callId,
			emOffer(ip) + "m=audio 10002 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n");
	}
}

TEST(EmergencyDialing, ARegisteredExtensionUnderAWildcardRuleKeepsTheSourceAddressCheck)
{
	{
		SCOPED_TRACE("102, from an address 101 did not register from: #497's 403");
		Bench b;
		b.handler->handle(emRegister("102", "192.168.77.12", "em-reg-102"));
		b.handler->setDialRule("1XX", "trunk", "911", 3);
		b.wire.clear();
		b.handler->handle(emShapedInvite("102", "192.168.77.99", "em-f-497-102", "", false));
		EXPECT_TRUE(b.wire.saw("Caller Not Registered From This Address")) << b.wire.dump();
		EXPECT_EQ(b.loopback()->lastMakeCallDestination(), "") << b.wire.dump();
		EXPECT_FALSE(b.wire.saw("INVITE sip:102@")) << b.wire.dump();
	}
	{
		SCOPED_TRACE("control: the same rule's 911 for 199 skips #497, as a dialed 911 does");
		Bench b;
		b.handler->handle(emRegister("102", "192.168.77.12", "em-reg-102"));
		b.handler->setDialRule("1XX", "trunk", "911", 3);
		b.wire.clear();
		b.handler->handle(emShapedInvite("199", "192.168.77.99", "em-f-497-199", "", false));
		EXPECT_EQ(b.loopback()->lastMakeCallDestination(), "911") << b.wire.dump();
	}
}

TEST(EmergencyDialing, ATrailingStarWildcardRuleYieldsToARegisteredExtension)
{
	{
		Bench b;
		b.handler->handle(emRegister("102", "192.168.77.12", "em-reg-102"));
		b.handler->setDialRule("1*", "trunk", "911", 3);
		ASSERT_EQ(b.handler->getDialRules().size(), 1u) << "precondition: the rule is stored";
		b.wire.clear();
		b.handler->handle(emInvite("101", "102", "192.168.77.11", "em-f-star-102"));
		EXPECT_EQ(b.loopback()->lastMakeCallDestination(), "") << b.wire.dump();
		EXPECT_TRUE(b.wire.saw("INVITE sip:102@")) << "102 rings:\n" << b.wire.dump();
	}
	{
		SCOPED_TRACE("control: 199 is not registered, so the rule makes it 911");
		Bench b;
		b.handler->handle(emRegister("102", "192.168.77.12", "em-reg-102"));
		b.handler->setDialRule("1*", "trunk", "911", 3);
		b.wire.clear();
		b.handler->handle(emInvite("101", "199", "192.168.77.11", "em-f-star-199"));
		EXPECT_EQ(b.loopback()->lastMakeCallDestination(), "911") << b.wire.dump();
	}
}

TEST(EmergencyDialing, ANineThreeThreeAWildcardRuleProducesIsATestCallWithEveryExemption)
{
	{
		SCOPED_TRACE("199 under 1XX -> 933, with Require: 100rel");
		Bench b;
		b.handler->handle(emRegister("102", "192.168.77.12", "em-reg-102"));
		b.handler->handle(emRegister("103", "192.168.77.13", "em-reg-103"));
		b.handler->setE911Config("103", "", "");
		b.handler->setDialRule("1XX", "trunk", "933", 3);
		b.wire.clear();
		b.handler->handle(emShapedInvite("199", "192.168.77.11", "em-f-933", "Require: 100rel\r\n", false));
		EXPECT_EQ(b.loopback()->lastMakeCallDestination(), "933") << b.wire.dump();
		EXPECT_FALSE(b.wire.saw("SIP/2.0 420")) << "the 933 gets the header gate's yield:\n" << b.wire.dump();
		EXPECT_TRUE(b.wire.saw("TEST: 933")) << "the notification is marked as a test:\n" << b.wire.dump();
		EXPECT_FALSE(b.wire.saw("EMERGENCY: 911")) << "a 933 never reads as a live 911:\n" << b.wire.dump();
	}
	{
		SCOPED_TRACE("the same rule yields to registered 102");
		Bench b;
		b.handler->handle(emRegister("102", "192.168.77.12", "em-reg-102"));
		b.handler->setDialRule("1XX", "trunk", "933", 3);
		b.wire.clear();
		b.handler->handle(emInvite("101", "102", "192.168.77.11", "em-f-933-102"));
		EXPECT_EQ(b.loopback()->lastMakeCallDestination(), "") << b.wire.dump();
		EXPECT_TRUE(b.wire.saw("INVITE sip:102@")) << b.wire.dump();
	}
}

TEST(EmergencyDialing, TheStreamCapAppliesToARegisteredExtensionAndYieldsOnlyToARealNineOneOne)
{
	{
		SCOPED_TRACE("registered 102 under 1XX -> 911: two audio streams get the ordinary 488");
		Bench b;
		b.handler->handle(emRegister("102", "192.168.77.12", "em-reg-102"));
		b.handler->setDialRule("1XX", "trunk", "911", 3);
		b.wire.clear();
		b.handler->handle(emTwoStreamInvite("102", "em-f-cap-102"));
		EXPECT_TRUE(b.wire.saw("SIP/2.0 488")) << b.wire.dump();
		EXPECT_EQ(b.loopback()->lastMakeCallDestination(), "") << b.wire.dump();
		EXPECT_FALSE(b.wire.saw("INVITE sip:102@")) << b.wire.dump();
	}
	{
		SCOPED_TRACE("the rule's 911 for 199: the cap yields");
		Bench b;
		b.handler->handle(emRegister("102", "192.168.77.12", "em-reg-102"));
		b.handler->setDialRule("1XX", "trunk", "911", 3);
		b.wire.clear();
		b.handler->handle(emTwoStreamInvite("199", "em-f-cap-199"));
		EXPECT_EQ(b.loopback()->lastMakeCallDestination(), "911") << b.wire.dump();
		EXPECT_FALSE(b.wire.saw("SIP/2.0 488")) << b.wire.dump();
	}
	{
		SCOPED_TRACE("a dialed 911: the cap yields");
		Bench b;
		b.wire.clear();
		b.handler->handle(emTwoStreamInvite("911", "em-f-cap-911"));
		EXPECT_EQ(b.loopback()->lastMakeCallDestination(), "911") << b.wire.dump();
		EXPECT_FALSE(b.wire.saw("SIP/2.0 488")) << b.wire.dump();
	}
}

TEST(EmergencyDialing, ALiteralNineOneOneRuleAfterAYieldedWildcardStillRoutesToNineOneOne)
{
	// "As if the wildcard rule did not exist": the next match is the literal
	// rule, and a literal rule never yields.
	Bench b;
	b.handler->handle(emRegister("102", "192.168.77.12", "em-reg-102"));
	b.handler->setDialRule("1XX", "trunk", "911", 3);
	b.handler->setDialRule("102", "trunk", "911", 3);
	ASSERT_EQ(b.handler->getDialRules().size(), 2u) << "precondition: both rules are stored";
	b.wire.clear();
	b.handler->handle(emInvite("101", "102", "192.168.77.11", "em-f-literal-after"));
	EXPECT_EQ(b.loopback()->lastMakeCallDestination(), "911") << b.wire.dump();
	EXPECT_FALSE(b.wire.saw("INVITE sip:102@")) << b.wire.dump();
}

// docs/API.md, "Emergency aliases: write them as literals" (pinned by
// tests/tools/test_dialplan_emergency_alias_doc.py): a wildcard alias such as
// 11X -> 911 lets a device that registers as 112 capture 112; a literal alias
// 112 -> 911 does not yield to it.
TEST(EmergencyDialing, AWildcardEmergencyAliasLetsARegistrationCaptureItAndALiteralOneDoesNot)
{
	{
		SCOPED_TRACE("11X -> 911, with a device registered as 112: 112 rings the device");
		Bench b;
		b.handler->handle(emRegister("112", "192.168.77.13", "em-reg-112"));
		ASSERT_TRUE(b.wire.saw("SIP/2.0 200 OK")) << "precondition: 112 registered:\n" << b.wire.dump();
		b.handler->setDialRule("11X", "trunk", "911", 3);
		b.wire.clear();
		b.handler->handle(emInvite("101", "112", "192.168.77.11", "em-doc-wild"));
		EXPECT_EQ(b.loopback()->lastMakeCallDestination(), "") << b.wire.dump();
		EXPECT_TRUE(b.wire.saw("INVITE sip:112@")) << b.wire.dump();
	}
	{
		SCOPED_TRACE("112 -> 911, with a device registered as 112: the call goes to 911");
		Bench b;
		b.handler->handle(emRegister("112", "192.168.77.13", "em-reg-112"));
		ASSERT_TRUE(b.wire.saw("SIP/2.0 200 OK")) << "precondition: 112 registered:\n" << b.wire.dump();
		b.handler->setDialRule("112", "trunk", "911", 3);
		b.wire.clear();
		b.handler->handle(emInvite("101", "112", "192.168.77.11", "em-doc-literal"));
		EXPECT_EQ(b.loopback()->lastMakeCallDestination(), "911") << b.wire.dump();
		EXPECT_FALSE(b.wire.saw("INVITE sip:112@")) << b.wire.dump();
	}
}
