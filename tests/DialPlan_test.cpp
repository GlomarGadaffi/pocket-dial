// DialPlan_test.cpp — Issue #69: the bounded, table-driven pattern → action dial
// plan that generalizes the ring-group mechanism.
//
// Three properties the feature lives or dies by, and one refactor guard:
//
//   1. PATTERN PRECEDENCE — rules are evaluated in TABLE ORDER and the first
//      match wins. Order is the operator's, not a specificity heuristic: a
//      catch-all listed first really does shadow the exact rule below it. That
//      is easy to "helpfully" break later by sorting most-specific-first, so it
//      is pinned here from both directions.
//   2. THE BOUNDED-SIZE CAP — POCKETDIAL_MAX_DIAL_RULES is a hard ceiling on the
//      table, enforced in DialPlan::upsert() itself (so every entry point
//      inherits it), asserted here through the pure class AND through
//      RequestsHandler::setDialRule/getDialRules.
//   3. FALLTHROUGH — a dialed number no rule matches must route EXACTLY as it did
//      before #69 existed. Asserted end-to-end through handle(), against a
//      populated rule table, by observing the wire messages the handler emits.
//
// Plus dispatch coverage for each of the three already-shipped actions the plan
// can select (ring group / hunt, page zone, park orbit), the stale-target 404,
// and a real-socket round-trip of POST /api/dialplan through HttpServer — the
// admin config surface, driven the same way AdminHttpGate_test.cpp drives it.

#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "AdminAuth.hpp"
#include "DialPlan.hpp"
#include "HttpServer.hpp"
#include "PbxConfig.hpp"
#include "PoolConfig.hpp"
#include "RequestsHandler.hpp"

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
#include <thread>

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

	// A minimally-valid INVITE carrying an SDP offer — onInvite()'s ordinary path
	// requires hasSdp() before it will allocate a session, and the park action
	// needs a real offer to hold. Same shape as Invite777SessionPool_test.cpp's.
	std::shared_ptr<SipMessage> makeInvite(const std::string& fromExt, const std::string& toExt,
	                                       const std::string& srcIp, const std::string& callId)
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

	// Records every message the handler puts on the wire, so a test can assert on
	// what a dialed number actually produced rather than on internal state.
	struct WireLog
	{
		std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>> sent;

		std::vector<std::string> raws() const
		{
			std::vector<std::string> out;
			out.reserve(sent.size());
			for (const auto& [addr, msg] : sent)
			{
				(void)addr;
				out.push_back(msg ? msg->toString() : std::string{});
			}
			return out;
		}

		// True if some emitted message is an INVITE fork aimed at `ext`.
		bool sawInviteTo(const std::string& ext) const
		{
			for (const auto& raw : raws())
			{
				if (raw.rfind("INVITE sip:" + ext + "@", 0) == 0) return true;
			}
			return false;
		}

		bool sawContaining(const std::string& needle) const
		{
			for (const auto& raw : raws())
			{
				if (raw.find(needle) != std::string::npos) return true;
			}
			return false;
		}

		size_t inviteCount() const
		{
			size_t n = 0;
			for (const auto& raw : raws())
			{
				if (raw.rfind("INVITE ", 0) == 0) ++n;
			}
			return n;
		}

		void clear() { sent.clear(); }
	};

	// A handler with 500 (the caller) and 600/601 (two callees) registered.
	// 500 -> 192.168.9.50, 600 -> 192.168.9.60, 601 -> 192.168.9.61.
	void registerThreePhones(RequestsHandler& handler)
	{
		handler.handle(makeRegister("500", "192.168.9.50", "reg-500"));
		handler.handle(makeRegister("600", "192.168.9.60", "reg-600"));
		handler.handle(makeRegister("601", "192.168.9.61", "reg-601"));
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// 1. Pattern grammar (pure — DialPlan.hpp only, no registrar linkage needed)
// ═══════════════════════════════════════════════════════════════════════════

TEST(DialPlanPattern, ExactMatchIsExact)
{
	EXPECT_TRUE(pbx::dialPatternMatches("601", "601"));
	EXPECT_FALSE(pbx::dialPatternMatches("601", "602"));
	EXPECT_FALSE(pbx::dialPatternMatches("601", "6010"));   // longer
	EXPECT_FALSE(pbx::dialPatternMatches("601", "60"));     // shorter
	EXPECT_FALSE(pbx::dialPatternMatches("601", ""));
}

TEST(DialPlanPattern, XMatchesExactlyOneDigit)
{
	EXPECT_TRUE(pbx::dialPatternMatches("6XX", "600"));
	EXPECT_TRUE(pbx::dialPatternMatches("6XX", "699"));
	EXPECT_TRUE(pbx::dialPatternMatches("6xx", "642"));     // lowercase accepted too
	EXPECT_FALSE(pbx::dialPatternMatches("6XX", "6001"));   // X is one char, not many
	EXPECT_FALSE(pbx::dialPatternMatches("6XX", "60"));
	EXPECT_FALSE(pbx::dialPatternMatches("6XX", "700"));
	EXPECT_FALSE(pbx::dialPatternMatches("XXX", "6A0"))
		<< "X means DIGIT, not any character";
}

TEST(DialPlanPattern, TrailingStarIsAPrefixMatch)
{
	EXPECT_TRUE(pbx::dialPatternMatches("6*", "6"));        // zero remaining chars
	EXPECT_TRUE(pbx::dialPatternMatches("6*", "60"));
	EXPECT_TRUE(pbx::dialPatternMatches("6*", "601"));
	EXPECT_TRUE(pbx::dialPatternMatches("6*", "6123456"));
	EXPECT_FALSE(pbx::dialPatternMatches("6*", "7"));
	EXPECT_FALSE(pbx::dialPatternMatches("6*", ""));
}

TEST(DialPlanPattern, LoneStarIsACatchAll)
{
	EXPECT_TRUE(pbx::dialPatternMatches("*", "601"));
	EXPECT_TRUE(pbx::dialPatternMatches("*", "anything"));
	EXPECT_TRUE(pbx::dialPatternMatches("*", ""));
}

TEST(DialPlanPattern, NonTrailingStarIsLiteral)
{
	// Star-codes (*8, the *PIN#code admin menu) are real dialable strings on
	// this box, so only a FINAL '*' is a wildcard — otherwise "*8" could never
	// mean the literal *8.
	EXPECT_TRUE(pbx::dialPatternMatches("*8", "*8"));
	EXPECT_FALSE(pbx::dialPatternMatches("*8", "8"));
	EXPECT_FALSE(pbx::dialPatternMatches("*8", "998"));
	EXPECT_TRUE(pbx::dialPatternMatches("*8*", "*8"))
		<< "leading '*' literal, trailing '*' wildcard";
	EXPECT_TRUE(pbx::dialPatternMatches("*8*", "*812"));
	EXPECT_FALSE(pbx::dialPatternMatches("*8*", "812"));
}

TEST(DialPlanPattern, MixedWildcards)
{
	EXPECT_TRUE(pbx::dialPatternMatches("2X*", "210"));
	EXPECT_TRUE(pbx::dialPatternMatches("2X*", "29"));
	EXPECT_FALSE(pbx::dialPatternMatches("2X*", "2"))
		<< "the X still needs its one digit before the star absorbs the rest";
	EXPECT_FALSE(pbx::dialPatternMatches("2X*", "2A1"));
}

TEST(DialPlanPattern, EmptyPatternNeverMatches)
{
	EXPECT_FALSE(pbx::dialPatternMatches("", "601"));
	EXPECT_FALSE(pbx::dialPatternMatches("", ""));
}

TEST(DialPlanPattern, ActionNamesRoundTrip)
{
	pbx::DialActionType a;
	ASSERT_TRUE(pbx::parseDialAction("group", a));
	EXPECT_EQ(a, pbx::DialActionType::RingGroup);
	EXPECT_STREQ(pbx::dialActionName(a), "group");

	ASSERT_TRUE(pbx::parseDialAction("page", a));
	EXPECT_EQ(a, pbx::DialActionType::PageZone);
	EXPECT_STREQ(pbx::dialActionName(a), "page");

	ASSERT_TRUE(pbx::parseDialAction("park", a));
	EXPECT_EQ(a, pbx::DialActionType::ParkOrbit);
	EXPECT_STREQ(pbx::dialActionName(a), "park");

	// Unknown names must be REJECTED, not silently defaulted — a corrupt NVS
	// record must never turn into some action the operator never configured.
	EXPECT_FALSE(pbx::parseDialAction("pickup", a));
	EXPECT_FALSE(pbx::parseDialAction("", a));
	EXPECT_FALSE(pbx::parseDialAction("GROUP", a));
}

TEST(DialPlanPattern, TokenSafetyRejectsBlobSeparators)
{
	// The NVS record is tab/newline delimited; a smuggled separator would corrupt
	// every rule after it on the next boot, so both fields are charset-checked.
	EXPECT_TRUE(pbx::isDialTokenSafe("6XX"));
	EXPECT_TRUE(pbx::isDialTokenSafe("*8#"));
	EXPECT_FALSE(pbx::isDialTokenSafe("6\tXX"));
	EXPECT_FALSE(pbx::isDialTokenSafe("6\nXX"));
	EXPECT_FALSE(pbx::isDialTokenSafe("6 XX"));
	EXPECT_FALSE(pbx::isDialTokenSafe("6@XX"));
	EXPECT_FALSE(pbx::isDialTokenSafe(""));
}

TEST(DialPlanPattern, ParkOrbitExtMatchesThisBuildsSlotCount)
{
	EXPECT_TRUE(pbx::isParkOrbitExt("700"));
	EXPECT_TRUE(pbx::isParkOrbitExt("70" + std::to_string(POCKETDIAL_PARK_SLOTS - 1)));
	EXPECT_FALSE(pbx::isParkOrbitExt("710"));
	EXPECT_FALSE(pbx::isParkOrbitExt("70"));
	EXPECT_FALSE(pbx::isParkOrbitExt("7000"));
	if (POCKETDIAL_PARK_SLOTS < 10)
	{
		EXPECT_FALSE(pbx::isParkOrbitExt("70" + std::to_string(POCKETDIAL_PARK_SLOTS)))
			<< "an orbit past this build's slot count is not a valid park target";
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// 2. Precedence: table order, first match wins
// ═══════════════════════════════════════════════════════════════════════════

TEST(DialPlanPrecedence, FirstMatchWinsInTableOrder)
{
	pbx::DialPlan plan;
	ASSERT_TRUE(plan.upsert({"601", pbx::DialActionType::RingGroup, "610"}));
	ASSERT_TRUE(plan.upsert({"6XX", pbx::DialActionType::RingGroup, "620"}));

	const pbx::DialRule* hit = plan.match("601");
	ASSERT_NE(hit, nullptr);
	EXPECT_EQ(hit->target, "610") << "the exact rule was listed first, so it wins";

	hit = plan.match("602");
	ASSERT_NE(hit, nullptr);
	EXPECT_EQ(hit->target, "620") << "602 only matches the wildcard rule";
}

TEST(DialPlanPrecedence, OrderNotSpecificityDecides)
{
	// The mirror image of the test above: with the WILDCARD listed first, it
	// shadows the exact rule below it. This is the property that breaks the
	// moment someone "improves" match() by sorting most-specific-first.
	pbx::DialPlan plan;
	ASSERT_TRUE(plan.upsert({"6XX", pbx::DialActionType::RingGroup, "620"}));
	ASSERT_TRUE(plan.upsert({"601", pbx::DialActionType::RingGroup, "610"}));

	const pbx::DialRule* hit = plan.match("601");
	ASSERT_NE(hit, nullptr);
	EXPECT_EQ(hit->target, "620")
		<< "table order is the semantics: a wildcard placed first shadows the "
		   "exact rule below it, even though the exact rule is 'more specific'";
}

TEST(DialPlanPrecedence, CatchAllFirstShadowsEverythingAfterIt)
{
	pbx::DialPlan plan;
	ASSERT_TRUE(plan.upsert({"*", pbx::DialActionType::PageZone, "980"}));
	ASSERT_TRUE(plan.upsert({"601", pbx::DialActionType::RingGroup, "610"}));

	for (const char* dialed : {"601", "602", "700", "abc"})
	{
		const pbx::DialRule* hit = plan.match(dialed);
		ASSERT_NE(hit, nullptr) << dialed;
		EXPECT_EQ(hit->target, "980") << dialed;
	}
}

TEST(DialPlanPrecedence, EditingARuleKeepsItsPosition)
{
	// Changing a rule's action/target must not silently re-order the plan —
	// re-appending an edited rule would change which numbers it captures.
	pbx::DialPlan plan;
	ASSERT_TRUE(plan.upsert({"6XX", pbx::DialActionType::RingGroup, "620"}));
	ASSERT_TRUE(plan.upsert({"7XX", pbx::DialActionType::RingGroup, "720"}));
	ASSERT_TRUE(plan.upsert({"6XX", pbx::DialActionType::PageZone, "981"}));

	ASSERT_EQ(plan.size(), 2u) << "an upsert on an existing pattern must not add a row";
	EXPECT_EQ(plan.rules()[0].pattern, "6XX");
	EXPECT_EQ(plan.rules()[0].action, pbx::DialActionType::PageZone);
	EXPECT_EQ(plan.rules()[0].target, "981");
	EXPECT_EQ(plan.rules()[1].pattern, "7XX");
}

TEST(DialPlanPrecedence, EraseRemovesOnlyThatRuleAndKeepsOrder)
{
	pbx::DialPlan plan;
	ASSERT_TRUE(plan.upsert({"1XX", pbx::DialActionType::RingGroup, "610"}));
	ASSERT_TRUE(plan.upsert({"2XX", pbx::DialActionType::RingGroup, "620"}));
	ASSERT_TRUE(plan.upsert({"3XX", pbx::DialActionType::RingGroup, "630"}));

	EXPECT_TRUE(plan.erase("2XX"));
	EXPECT_FALSE(plan.erase("2XX")) << "erasing a pattern that is gone reports false";
	ASSERT_EQ(plan.size(), 2u);
	EXPECT_EQ(plan.rules()[0].pattern, "1XX");
	EXPECT_EQ(plan.rules()[1].pattern, "3XX");
}

TEST(DialPlanPrecedence, NoRuleMatchesReturnsNull)
{
	pbx::DialPlan plan;
	ASSERT_TRUE(plan.upsert({"6XX", pbx::DialActionType::RingGroup, "620"}));
	EXPECT_EQ(plan.match("500"), nullptr);
	EXPECT_EQ(plan.match(""), nullptr);

	pbx::DialPlan emptyPlan;
	EXPECT_EQ(emptyPlan.match("601"), nullptr);
	EXPECT_TRUE(emptyPlan.empty());
}

// ═══════════════════════════════════════════════════════════════════════════
// 3. The bounded-size cap (POCKETDIAL_MAX_DIAL_RULES)
// ═══════════════════════════════════════════════════════════════════════════

TEST(DialPlanCap, UpsertRefusesNewRulesOnceFull)
{
	pbx::DialPlan plan;
	for (int i = 0; i < POCKETDIAL_MAX_DIAL_RULES; ++i)
	{
		SCOPED_TRACE(i);
		ASSERT_TRUE(plan.upsert({"r" + std::to_string(i), pbx::DialActionType::RingGroup, "610"}));
	}
	ASSERT_EQ(static_cast<int>(plan.size()), POCKETDIAL_MAX_DIAL_RULES);

	EXPECT_FALSE(plan.upsert({"overflow", pbx::DialActionType::RingGroup, "610"}));
	EXPECT_EQ(static_cast<int>(plan.size()), POCKETDIAL_MAX_DIAL_RULES)
		<< "a refused rule must not grow the table";
	EXPECT_EQ(plan.match("overflow"), nullptr)
		<< "a refused rule must not be routable either";
}

TEST(DialPlanCap, FullTableIsStillEditableAndFreeableInPlace)
{
	// A hard cap that also made the table read-only would be a trap: the operator
	// could no longer fix the very rule that filled it.
	pbx::DialPlan plan;
	for (int i = 0; i < POCKETDIAL_MAX_DIAL_RULES; ++i)
	{
		ASSERT_TRUE(plan.upsert({"r" + std::to_string(i), pbx::DialActionType::RingGroup, "610"}));
	}

	EXPECT_TRUE(plan.upsert({"r0", pbx::DialActionType::PageZone, "982"}))
		<< "editing an EXISTING rule is not a growth operation and must succeed at cap";
	EXPECT_EQ(static_cast<int>(plan.size()), POCKETDIAL_MAX_DIAL_RULES);
	EXPECT_EQ(plan.rules()[0].target, "982");

	// Freeing one slot lets exactly one new rule in again.
	ASSERT_TRUE(plan.erase("r0"));
	EXPECT_TRUE(plan.upsert({"fresh", pbx::DialActionType::RingGroup, "610"}));
	EXPECT_FALSE(plan.upsert({"fresh2", pbx::DialActionType::RingGroup, "610"}));
}

TEST(DialPlanCap, SetDialRuleEnforcesTheCapThroughTheHandler)
{
	// The same ceiling, observed through the public config API + dashboard getter
	// the HTTP admin surface uses — not just the pure class.
	RequestsHandler handler("192.168.9.1", 5060,
		[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});

	for (int i = 0; i < POCKETDIAL_MAX_DIAL_RULES; ++i)
	{
		handler.setDialRule("9" + std::to_string(100 + i), "group", "610");
	}
	ASSERT_EQ(static_cast<int>(handler.getDialRules().size()), POCKETDIAL_MAX_DIAL_RULES);

	handler.setDialRule("overflow1", "group", "610");
	handler.setDialRule("overflow2", "page", "980");
	EXPECT_EQ(static_cast<int>(handler.getDialRules().size()), POCKETDIAL_MAX_DIAL_RULES)
		<< "setDialRule must drop rules past POCKETDIAL_MAX_DIAL_RULES";

	// Deleting one frees exactly one slot.
	handler.setDialRule("9100", "", "");
	ASSERT_EQ(static_cast<int>(handler.getDialRules().size()), POCKETDIAL_MAX_DIAL_RULES - 1);
	handler.setDialRule("overflow3", "group", "610");
	EXPECT_EQ(static_cast<int>(handler.getDialRules().size()), POCKETDIAL_MAX_DIAL_RULES);
}

TEST(DialPlanCap, HandlerGetterReportsRulesInTableOrder)
{
	RequestsHandler handler("192.168.9.1", 5060,
		[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});

	handler.setDialRule("1XX", "group", "610");
	handler.setDialRule("2XX", "page", "981");
	handler.setDialRule("3XX", "park", "701");

	auto rules = handler.getDialRules();
	ASSERT_EQ(rules.size(), 3u);
	EXPECT_EQ(std::get<0>(rules[0]), "1XX");
	EXPECT_EQ(std::get<1>(rules[0]), "group");
	EXPECT_EQ(std::get<2>(rules[0]), "610");
	EXPECT_EQ(std::get<0>(rules[1]), "2XX");
	EXPECT_EQ(std::get<1>(rules[1]), "page");
	EXPECT_EQ(std::get<0>(rules[2]), "3XX");
	EXPECT_EQ(std::get<1>(rules[2]), "park");
	EXPECT_EQ(std::get<2>(rules[2]), "701");

	// tick() rebuilds the snapshot wholesale; the order must survive that swap.
	handler.tick();
	auto afterTick = handler.getDialRules();
	ASSERT_EQ(afterTick.size(), 3u);
	EXPECT_EQ(std::get<0>(afterTick[0]), "1XX");
	EXPECT_EQ(std::get<0>(afterTick[1]), "2XX");
	EXPECT_EQ(std::get<0>(afterTick[2]), "3XX");
}

TEST(DialPlanCap, SetDialRuleRejectsMalformedRules)
{
	RequestsHandler handler("192.168.9.1", 5060,
		[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});

	handler.setDialRule("6\tXX", "group", "610");        // tab would corrupt the NVS blob
	handler.setDialRule("6XX", "group", "61\n0");        // …and so would a newline
	handler.setDialRule("6XX", "pickup", "610");         // unknown action (#68 is not on main)
	handler.setDialRule("6XX", "page", "601");           // page target is not a 98x zone
	handler.setDialRule("6XX", "park", "799");           // park target is not an orbit
	handler.setDialRule("777", "group", "610");          // reserved: routed before the plan
	handler.setDialRule("999", "group", "610");
	handler.setDialRule("440", "group", "610");

	EXPECT_TRUE(handler.getDialRules().empty())
		<< "every malformed rule above must be dropped, not stored";

	// …and the valid shapes of each still land.
	handler.setDialRule("6XX", "page", "981");
	handler.setDialRule("7XX", "park", "701");
	EXPECT_EQ(handler.getDialRules().size(), 2u);
}

// ═══════════════════════════════════════════════════════════════════════════
// 4. Fallthrough: an unmatched number routes exactly as it did before #69
// ═══════════════════════════════════════════════════════════════════════════

TEST(DialPlanRouting, UnmatchedNumberFallsThroughToNormalExtensionRouting)
{
	WireLog wire;
	RequestsHandler handler("192.168.9.1", 5060,
		[&wire](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			wire.sent.emplace_back(addr, std::move(msg));
		});
	registerThreePhones(handler);

	// A populated, non-empty table — so this is really testing "no rule matched",
	// not "the dial plan is switched off".
	handler.setRingGroup("610", "600,601", "ringall");
	handler.setDialRule("2XX", "group", "610");
	handler.setDialRule("3*", "page", "980");
	ASSERT_EQ(handler.getDialRules().size(), 2u);

	wire.clear();
	handler.handle(makeInvite("500", "600", "192.168.9.50", "fallthrough-1"));

	EXPECT_TRUE(wire.sawInviteTo("600"))
		<< "600 matches no rule, so it must ring the ordinary way";
	EXPECT_FALSE(wire.sawInviteTo("601"))
		<< "it must NOT have been fanned out as if it were the 610 group";
	EXPECT_EQ(wire.inviteCount(), 1u) << "exactly one leg, as before #69";
	EXPECT_FALSE(wire.sawContaining("404 Not Found"));
	EXPECT_FALSE(wire.sawContaining("480 Temporarily Unavailable"));
}

TEST(DialPlanRouting, UnmatchedUnknownNumberStill404s)
{
	// The other half of "no behavior change": an unmatched number that is not a
	// real extension must still get the pre-#69 answer, not a dial-plan error.
	WireLog wire;
	RequestsHandler handler("192.168.9.1", 5060,
		[&wire](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			wire.sent.emplace_back(addr, std::move(msg));
		});
	registerThreePhones(handler);
	handler.setRingGroup("610", "600,601", "ringall");
	handler.setDialRule("2XX", "group", "610");

	wire.clear();
	handler.handle(makeInvite("500", "489", "192.168.9.50", "fallthrough-2"));

	EXPECT_TRUE(wire.sawContaining("404 Not Found"));
	EXPECT_EQ(wire.inviteCount(), 0u);
}

TEST(DialPlanRouting, ReservedCodesAreRoutedBeforeThePlanCanSeeThem)
{
	// A catch-all rule must not be able to swallow the built-in virtual
	// extensions — that is what makes the plan safe to add to a live box.
	WireLog wire;
	RequestsHandler handler("192.168.9.1", 5060,
		[&wire](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			wire.sent.emplace_back(addr, std::move(msg));
		});
	registerThreePhones(handler);
	handler.setPageZone("980", "600");
	handler.setDialRule("*", "page", "980");
	ASSERT_EQ(handler.getDialRules().size(), 1u);

	wire.clear();
	handler.handle(makeInvite("500", "777", "192.168.9.50", "reserved-777"));
	EXPECT_TRUE(wire.sawContaining("SIP/2.0 200 OK"))
		<< "777 must still be the SDP echo test, not a page";
	EXPECT_FALSE(wire.sawInviteTo("600"));

	// …and a configured ring-group extension likewise resolves as itself.
	handler.setRingGroup("610", "600,601", "ringall");
	wire.clear();
	handler.handle(makeInvite("500", "610", "192.168.9.50", "reserved-610"));
	EXPECT_TRUE(wire.sawInviteTo("600"));
	EXPECT_TRUE(wire.sawInviteTo("601"))
		<< "610 is a real group, so it fans out as a group — the catch-all page "
		   "rule must not have intercepted it";
}

// ═══════════════════════════════════════════════════════════════════════════
// 5. Dispatch into each already-shipped action
// ═══════════════════════════════════════════════════════════════════════════

TEST(DialPlanRouting, GroupActionFansOutTheRingGroup)
{
	WireLog wire;
	RequestsHandler handler("192.168.9.1", 5060,
		[&wire](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			wire.sent.emplace_back(addr, std::move(msg));
		});
	registerThreePhones(handler);
	handler.setRingGroup("610", "600,601", "ringall");
	handler.setDialRule("2XX", "group", "610");

	wire.clear();
	handler.handle(makeInvite("500", "250", "192.168.9.50", "plan-group"));

	EXPECT_TRUE(wire.sawInviteTo("600"));
	EXPECT_TRUE(wire.sawInviteTo("601"));
	EXPECT_TRUE(wire.sawContaining("180 Ringing"));
	EXPECT_FALSE(wire.sawContaining("P-Auto-Answer"))
		<< "a ring group rings normally — the intercom headers are the 999/page path";
}

TEST(DialPlanRouting, GroupActionInHuntModeRingsOneMemberAtATime)
{
	WireLog wire;
	RequestsHandler handler("192.168.9.1", 5060,
		[&wire](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			wire.sent.emplace_back(addr, std::move(msg));
		});
	registerThreePhones(handler);
	handler.setRingGroup("620", "600,601", "hunt");
	handler.setDialRule("2XX", "group", "620");

	wire.clear();
	handler.handle(makeInvite("500", "222", "192.168.9.50", "plan-hunt"));

	EXPECT_EQ(wire.inviteCount(), 1u) << "hunt rings members sequentially, one at a time";
	EXPECT_TRUE(wire.sawInviteTo("600"));
	EXPECT_FALSE(wire.sawInviteTo("601"));
	EXPECT_TRUE(wire.sawContaining("180 Ringing"));

	// The session must carry the REAL group extension, not the dialed alias —
	// getGroupExt() feeds the hunt-exhausted CDR and the no-answer Contact.
	auto session = handler.getSession("Call-ID: plan-hunt");
	ASSERT_TRUE(session.has_value());
	EXPECT_EQ(session.value()->getGroupExt(), "620")
		<< "a dial-rule alias must not leak into the session's group identity";
}

TEST(DialPlanRouting, PageActionForksTheZoneWithIntercomHeaders)
{
	WireLog wire;
	RequestsHandler handler("192.168.9.1", 5060,
		[&wire](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			wire.sent.emplace_back(addr, std::move(msg));
		});
	registerThreePhones(handler);
	handler.setPageZone("981", "600,601");
	handler.setDialRule("55", "page", "981");

	wire.clear();
	handler.handle(makeInvite("500", "55", "192.168.9.50", "plan-page"));

	EXPECT_TRUE(wire.sawInviteTo("600"));
	EXPECT_TRUE(wire.sawInviteTo("601"));
	EXPECT_TRUE(wire.sawContaining("P-Auto-Answer"))
		<< "a zone page is an intercom fork — auto-answer headers must be present";
}

TEST(DialPlanRouting, ParkActionParksTheCallerOnTheOrbit)
{
	WireLog wire;
	RequestsHandler handler("192.168.9.1", 5060,
		[&wire](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			wire.sent.emplace_back(addr, std::move(msg));
		});
	registerThreePhones(handler);
	handler.setDialRule("8XX", "park", "701");

	wire.clear();
	handler.handle(makeInvite("500", "800", "192.168.9.50", "plan-park"));

	EXPECT_TRUE(wire.sawContaining("SIP/2.0 200 OK"));
	EXPECT_TRUE(wire.sawContaining("a=inactive"))
		<< "parking answers with the hold SDP, exactly as dialing 701 directly does";
	EXPECT_TRUE(wire.sawContaining("sip:701@"))
		<< "the answer's Contact must name the orbit the rule targeted";
}

TEST(DialPlanRouting, MatchedRuleWithAStaleTargetAnswers404NotAMisroutedCall)
{
	// The rule matched, so the plan owns the call — but its group was deleted
	// after the rule was written. Falling through here would ring whichever real
	// extension happens to share the dialed digits, i.e. connect the caller to
	// the wrong person. A 404 is the diagnosable answer.
	WireLog wire;
	RequestsHandler handler("192.168.9.1", 5060,
		[&wire](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			wire.sent.emplace_back(addr, std::move(msg));
		});
	registerThreePhones(handler);
	handler.setRingGroup("610", "600,601", "ringall");
	handler.setDialRule("6XX", "group", "610");

	handler.setRingGroup("610", "", "ringall");        // group deleted, rule left behind
	ASSERT_TRUE(handler.getRingGroups().empty());
	ASSERT_EQ(handler.getDialRules().size(), 1u);

	wire.clear();
	handler.handle(makeInvite("500", "600", "192.168.9.50", "plan-stale"));

	EXPECT_TRUE(wire.sawContaining("404 Not Found"));
	EXPECT_FALSE(wire.sawInviteTo("600"))
		<< "a stale rule must not silently fall through and ring extension 600";
}

TEST(DialPlanRouting, GroupActionAnswers480WhenNoMemberIsRegistered)
{
	// The rule and its group are both fine; the members just aren't online. This
	// is the group path's own pre-existing answer, reached through the dial plan.
	WireLog wire;
	RequestsHandler handler("192.168.9.1", 5060,
		[&wire](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			wire.sent.emplace_back(addr, std::move(msg));
		});
	handler.handle(makeRegister("500", "192.168.9.50", "reg-500"));
	handler.setRingGroup("610", "700,701", "ringall");   // never-registered members
	handler.setDialRule("2XX", "group", "610");

	wire.clear();
	handler.handle(makeInvite("500", "250", "192.168.9.50", "plan-offline"));

	EXPECT_TRUE(wire.sawContaining("480 Temporarily Unavailable"));
	EXPECT_EQ(wire.inviteCount(), 0u);
}

// ═══════════════════════════════════════════════════════════════════════════
// 6. The HTTP admin config surface (real socket round-trip through HttpServer)
// ═══════════════════════════════════════════════════════════════════════════

namespace
{
	// Minimal blocking HTTP POST over a raw socket, mirroring
	// AdminHttpGate_test.cpp's helper. No Origin header → treated as a direct
	// request by isSameOrigin(), which is what curl/the dashboard's own fetch do.
	std::string httpPostRaw(int port, const std::string& path, const std::string& body)
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
		std::string req = "POST " + path + " HTTP/1.1\r\n"
			"Host: 127.0.0.1\r\n"
			"Content-Type: application/x-www-form-urlencoded\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n"
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

	int statusOf(const std::string& resp)
	{
		size_t sp1 = resp.find(' ');
		if (sp1 == std::string::npos) return -1;
		size_t sp2 = resp.find(' ', sp1 + 1);
		if (sp2 == std::string::npos) return -1;
		return std::atoi(resp.substr(sp1 + 1, sp2 - sp1 - 1).c_str());
	}

	std::string httpGetRaw(int port, const std::string& path)
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
		std::string req = "GET " + path + " HTTP/1.1\r\n"
			"Host: 127.0.0.1\r\n"
			"Connection: close\r\n\r\n";
		send(s, req.c_str(), static_cast<int>(req.size()), 0);

		std::string resp;
		char buf[4096];
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
}

TEST(DialPlanHttp, PostApiDialPlanUpsertsAndDeletesThroughTheAdminSurface)
{
	AdminAuth::clearCredential();   // unprovisioned → same-origin gate only

	RequestsHandler handler("192.168.9.1", 5060,
		[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});
	HttpServer server("127.0.0.1", 18090, nullptr);
	server.attachHandler(&handler);
	server.start();
	std::this_thread::sleep_for(std::chrono::milliseconds(50));

	EXPECT_EQ(statusOf(httpPostRaw(18090, "/api/dialplan",
		"pattern=2XX&action=group&target=610")), 200);
	EXPECT_EQ(statusOf(httpPostRaw(18090, "/api/dialplan",
		"pattern=3XX&action=page&target=981")), 200);

	// '*' and '#' are the grammar's own characters AND form-encoding metacharacters,
	// so a rule that uses them has to survive getFormParam's url-decoding intact —
	// a plan whose wildcard cannot be configured over the API is no plan at all.
	EXPECT_EQ(statusOf(httpPostRaw(18090, "/api/dialplan",
		"pattern=6*&action=group&target=610")), 200);
	EXPECT_EQ(statusOf(httpPostRaw(18090, "/api/dialplan",
		"pattern=%239&action=park&target=701")), 200);

	auto rules = handler.getDialRules();
	ASSERT_EQ(rules.size(), 4u);
	EXPECT_EQ(std::get<0>(rules[0]), "2XX");
	EXPECT_EQ(std::get<1>(rules[0]), "group");
	EXPECT_EQ(std::get<2>(rules[0]), "610");
	EXPECT_EQ(std::get<0>(rules[1]), "3XX");
	EXPECT_EQ(std::get<1>(rules[1]), "page");
	EXPECT_EQ(std::get<0>(rules[2]), "6*")
		<< "a trailing-star prefix rule must round-trip the form body verbatim";
	EXPECT_EQ(std::get<0>(rules[3]), "#9")
		<< "a '#' pattern must survive url-decoding as the literal character";

	// The rule table is readable back out of /api/status, in table order.
	std::string status = httpGetRaw(18090, "/api/status");
	EXPECT_NE(status.find("\"dialplan\":["), std::string::npos);
	size_t first = status.find("\"pattern\":\"2XX\"");
	size_t second = status.find("\"pattern\":\"3XX\"");
	EXPECT_NE(first, std::string::npos);
	EXPECT_NE(second, std::string::npos);
	EXPECT_LT(first, second) << "/api/status must emit the plan in evaluation order";

	// An empty target deletes — including a pattern carrying a wildcard.
	EXPECT_EQ(statusOf(httpPostRaw(18090, "/api/dialplan", "pattern=2XX&target=")), 200);
	EXPECT_EQ(statusOf(httpPostRaw(18090, "/api/dialplan", "pattern=6*&target=")), 200);
	rules = handler.getDialRules();
	ASSERT_EQ(rules.size(), 2u);
	EXPECT_EQ(std::get<0>(rules[0]), "3XX");
	EXPECT_EQ(std::get<0>(rules[1]), "#9");
}

TEST(DialPlanHttp, PostApiDialPlanRejectsBadParametersWith400)
{
	AdminAuth::clearCredential();

	RequestsHandler handler("192.168.9.1", 5060,
		[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});
	HttpServer server("127.0.0.1", 18091, nullptr);
	server.attachHandler(&handler);
	server.start();
	std::this_thread::sleep_for(std::chrono::milliseconds(50));

	EXPECT_EQ(statusOf(httpPostRaw(18091, "/api/dialplan", "action=group&target=610")), 400)
		<< "missing pattern";
	EXPECT_EQ(statusOf(httpPostRaw(18091, "/api/dialplan",
		"pattern=2XX&action=pickup&target=610")), 400) << "unknown action";
	EXPECT_EQ(statusOf(httpPostRaw(18091, "/api/dialplan",
		"pattern=2XX&action=page&target=601")), 400) << "page target is not a 98x zone";
	EXPECT_EQ(statusOf(httpPostRaw(18091, "/api/dialplan",
		"pattern=2XX&action=park&target=799")), 400) << "park target is not an orbit";
	EXPECT_EQ(statusOf(httpPostRaw(18091, "/api/dialplan",
		"pattern=777&action=group&target=610")), 400) << "reserved extension as a pattern";
	EXPECT_EQ(statusOf(httpPostRaw(18091, "/api/dialplan",
		"pattern=2%20XX&action=group&target=610")), 400) << "unsafe character in pattern";

	EXPECT_TRUE(handler.getDialRules().empty())
		<< "no rejected request may have reached the rule table";
}
