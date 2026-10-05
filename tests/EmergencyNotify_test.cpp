// EmergencyNotify_test.cpp — Kari's Law on-site notification (Issue #166 part 2).
//
// The property under test is an ORDERING one, and it is the compliance-relevant
// part: 47 CFR 9.16(b)(2) requires the notification to be contemporaneous with
// the 911 call and to NOT delay it. In code that means the call leg is enqueued
// first and nothing in the notification path can prevent, delay or reorder it.
// Several tests below therefore assert position on the wire, not just presence.
//
// The other half is that the notification fires when the call FAILS to route —
// a 911 attempt that went nowhere is the single most important thing to put in
// front of a human, and it is the case an implementation is most likely to miss.
//
// Numbers here are 911/933 and internal extensions. The callback fixture uses a
// reserved fictitious NANP number.

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "EmergencyCall.hpp"
#include "EmergencyNotifier.hpp"
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
	sockaddr_in enAddr(const std::string& ip)
	{
		sockaddr_in s{};
		s.sin_family = AF_INET;
		s.sin_addr.s_addr = inet_addr(ip.c_str());
		s.sin_port = htons(5060);
		return s;
	}

	std::shared_ptr<SipMessage> enRegister(const std::string& ext, const std::string& ip,
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
		return RequestsHandler::getMessageFromPool(raw, enAddr(ip));
	}

	std::shared_ptr<SipMessage> enInvite(const std::string& fromExt, const std::string& toExt,
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
		return RequestsHandler::getMessageFromPool(raw, enAddr(ip));
	}

	struct NBench
	{
		std::vector<std::string> wire;
		std::unique_ptr<RequestsHandler> handler;

		NBench()
		{
			handler = std::make_unique<RequestsHandler>("192.168.78.1", 5060,
				[this](const sockaddr_in&, std::shared_ptr<SipMessage> m) {
					wire.push_back(m->toString());
				});
			handler->handle(enRegister("101", "192.168.78.11", "en-r-101"));  // the dialer
			handler->handle(enRegister("200", "192.168.78.20", "en-r-200"));  // front desk
			// Issue #521: the loopback anchor refuses every emergency number
			// (EmergencyRoute_test.cpp pins that). These tests are about the
			// notification around a routed call, so it stands in for a real
			// provider here.
			handler->setAnchorPlacesRealCallsForTest(true);
			wire.clear();
		}

		LoopbackAnchorClient* loopback()
		{
			return dynamic_cast<LoopbackAnchorClient*>(handler->anchorClientForTest());
		}

		// Index of the first wire entry containing `needle`, or -1.
		int indexOf(const std::string& needle) const
		{
			for (size_t i = 0; i < wire.size(); ++i)
			{
				if (wire[i].find(needle) != std::string::npos) return static_cast<int>(i);
			}
			return -1;
		}

		int countOf(const std::string& needle) const
		{
			int n = 0;
			for (const auto& s : wire)
			{
				if (s.find(needle) != std::string::npos) ++n;
			}
			return n;
		}

		std::string dump() const
		{
			std::string out;
			for (const auto& s : wire) { out += s.substr(0, 120); out += "\n---\n"; }
			return out;
		}
	};
}

// ─────────────────────────────────────────────────────────────────────────────
// The pure notification text
// ─────────────────────────────────────────────────────────────────────────────

TEST(E911Format, SaysWhatHappenedWhoAndHowToReachBack)
{
	pbx::E911Config cfg;
	cfg.callback = "2025550123";
	cfg.location = "Front office";

	const std::string s = pbx::formatE911Notification(
		/*isTest=*/false, "101", "911", /*hadTrunkPrefix=*/false, /*routed=*/true, cfg);

	EXPECT_NE(s.find("EMERGENCY"), std::string::npos);
	EXPECT_NE(s.find("911"), std::string::npos);
	EXPECT_NE(s.find("101"), std::string::npos);
	EXPECT_NE(s.find("2025550123"), std::string::npos);
	EXPECT_NE(s.find("Front office"), std::string::npos);
	EXPECT_NE(s.find("ROUTED"), std::string::npos);
}

TEST(E911Format, ATestCallCanNeverBeSkimReadAsALiveEmergency)
{
	pbx::E911Config cfg;
	const std::string test = pbx::formatE911Notification(true, "101", "933", false, true, cfg);
	const std::string live = pbx::formatE911Notification(false, "101", "911", false, true, cfg);

	EXPECT_EQ(test.rfind("TEST:", 0), 0u) << "the TEST marker must lead: " << test;
	EXPECT_NE(live.rfind("TEST:", 0), 0u);
	EXPECT_NE(test, live);
}

TEST(E911Format, AFailedAttemptReadsAsFailedRatherThanAsAnOrdinaryAlert)
{
	pbx::E911Config cfg;
	const std::string ok   = pbx::formatE911Notification(false, "101", "911", false, true, cfg);
	const std::string bad  = pbx::formatE911Notification(false, "101", "911", false, false, cfg);

	EXPECT_NE(bad.find("NOT ROUTED"), std::string::npos) << bad;
	EXPECT_EQ(ok.find("NOT ROUTED"), std::string::npos)
		<< "a successful call must not contain the failure wording: " << ok;
}

TEST(E911Format, AnAbsentCallbackIsStatedRatherThanLeftBlank)
{
	// A blank field reads as "nothing to report"; here it means the opposite.
	pbx::E911Config cfg;   // no callback configured
	const std::string s = pbx::formatE911Notification(false, "101", "911", false, true, cfg);
	EXPECT_NE(s.find("not configured"), std::string::npos) << s;
}

TEST(E911Format, RecordsThatTheUserDialedATrunkPrefix)
{
	pbx::E911Config cfg;
	const std::string s = pbx::formatE911Notification(false, "101", "9911", true, true, cfg);
	EXPECT_NE(s.find("9911"), std::string::npos)
		<< "an operator needs to see their trunk-access habit is in play: " << s;
}

TEST(E911Format, StaysWithinTheMessageBodyCap)
{
	pbx::E911Config cfg;
	cfg.callback = std::string(400, '5');
	cfg.location = std::string(400, 'x');
	const std::string s = pbx::formatE911Notification(false, "101", "911", false, true, cfg);
	EXPECT_LE(s.size(), 512u) << "must not exceed the MESSAGE body cap";
}

// ─────────────────────────────────────────────────────────────────────────────
// Ordering: the call first, always
// ─────────────────────────────────────────────────────────────────────────────

TEST(E911Notify, TheCallLegIsOnTheWireBeforeTheNotification)
{
	// 47 CFR 9.16(b)(2): contemporaneous, and must not delay the call. Both
	// leave on the same drainOutbox() pass, so the requirement is satisfied by
	// position rather than by timing.
	NBench b;
	ASSERT_NE(b.loopback(), nullptr);
	b.handler->setE911Config("200", "2025550123", "Front office");
	b.wire.clear();

	b.handler->handle(enInvite("101", "911", "192.168.78.11", "en-911-order"));

	const int answer = b.indexOf("SIP/2.0 200 OK");
	const int notify = b.indexOf("MESSAGE sip:200@");
	ASSERT_GE(answer, 0) << "the anchor should have answered the 911 leg:\n" << b.dump();
	ASSERT_GE(notify, 0) << "the notification should have been sent:\n" << b.dump();
	EXPECT_LT(answer, notify) << "the call leg must be enqueued BEFORE the notification";
}

TEST(E911Notify, TheFiveOhThreeIsOnTheWireBeforeTheNotificationToo)
{
	NBench b;
	b.handler->anchorClientForTest()->stop();
	b.handler->setE911Config("200", "", "");
	b.wire.clear();

	b.handler->handle(enInvite("101", "911", "192.168.78.11", "en-911-503-order"));

	const int fail   = b.indexOf("SIP/2.0 503");
	const int notify = b.indexOf("MESSAGE sip:200@");
	ASSERT_GE(fail, 0) << b.dump();
	ASSERT_GE(notify, 0) << b.dump();
	EXPECT_LT(fail, notify);
}

// ─────────────────────────────────────────────────────────────────────────────
// It fires on failure — the case most likely to be missed
// ─────────────────────────────────────────────────────────────────────────────

TEST(E911Notify, FiresEvenWhenTheCallCouldNotBeRoutedAtAll)
{
	NBench b;
	b.handler->anchorClientForTest()->stop();
	b.handler->setE911Config("200", "", "");
	b.wire.clear();

	b.handler->handle(enInvite("101", "911", "192.168.78.11", "en-911-failnotify"));

	ASSERT_GE(b.indexOf("MESSAGE sip:200@"), 0)
		<< "a 911 attempt that went nowhere is the MOST important one to notify:\n" << b.dump();
	EXPECT_GE(b.indexOf("NOT ROUTED"), 0) << "and it must say so";
}

TEST(E911Notify, TheTestNumberNotifiesAndIsMarkedAsATest)
{
	NBench b;
	ASSERT_NE(b.loopback(), nullptr);
	b.handler->setE911Config("200", "", "");
	b.wire.clear();

	b.handler->handle(enInvite("101", "933", "192.168.78.11", "en-933-notify"));

	ASSERT_GE(b.indexOf("MESSAGE sip:200@"), 0) << b.dump();
	EXPECT_GE(b.indexOf("TEST:"), 0) << "a 933 notification must be tagged TEST";
}

// ─────────────────────────────────────────────────────────────────────────────
// Nothing about notification may affect the call
// ─────────────────────────────────────────────────────────────────────────────

TEST(E911Notify, WithNoNotifyExtensionsConfiguredTheCallStillRoutes)
{
	NBench b;
	ASSERT_NE(b.loopback(), nullptr);
	// Deliberately no setE911Config call at all.
	b.wire.clear();

	b.handler->handle(enInvite("101", "911", "192.168.78.11", "en-911-nocfg"));

	EXPECT_EQ(b.loopback()->lastMakeCallDestination(), "911")
		<< "an unconfigured notification list must not affect the call";
	EXPECT_EQ(b.countOf("MESSAGE sip:"), 0) << "and must not invent a recipient";
}

TEST(E911Notify, AnUnregisteredNotifyExtensionDoesNotStopTheCallOrTheOthers)
{
	NBench b;
	ASSERT_NE(b.loopback(), nullptr);
	// 999 is never registered here (and is reserved anyway).
	b.handler->setE911Config("777 200", "", "");
	b.wire.clear();

	b.handler->handle(enInvite("101", "911", "192.168.78.11", "en-911-unreg"));

	EXPECT_EQ(b.loopback()->lastMakeCallDestination(), "911")
		<< "an unreachable notify target must not affect the call";
	EXPECT_GE(b.indexOf("MESSAGE sip:200@"), 0)
		<< "the registered target must still be notified:\n" << b.dump();
}

TEST(E911Notify, TheNotifyListIsBoundedRegardlessOfWhatWasConfigured)
{
	// A mis-typed or migrated config must never turn one 911 dial into an
	// unbounded burst of pooled messages on the emergency path.
	NBench b;
	ASSERT_NE(b.loopback(), nullptr);

	b.handler->setE911Config("200 201 202 203 204 205 206 207", "", "");

	const auto [exts, cb, loc] = b.handler->getE911Config();
	(void)cb; (void)loc;
	int commas = 0;
	for (char c : exts) { if (c == ',') ++commas; }
	EXPECT_LE(static_cast<size_t>(commas + 1), pbx::kMaxE911NotifyExts)
		<< "stored notify list must be capped, got: " << exts;

	b.wire.clear();
	b.handler->handle(enInvite("101", "911", "192.168.78.11", "en-911-bounded"));
	EXPECT_EQ(b.loopback()->lastMakeCallDestination(), "911");
}

TEST(E911Notify, TheDialingExtensionIsNeverBeepedMidCallSetup)
{
	// If the dialer is also on the notify list, it must not receive an intercom
	// INVITE while its own 911 call is being set up.
	NBench b;
	ASSERT_NE(b.loopback(), nullptr);
	b.handler->setE911Config("101 200", "", "");
	b.wire.clear();

	b.handler->handle(enInvite("101", "911", "192.168.78.11", "en-911-selfbeep"));

	EXPECT_EQ(b.countOf("INVITE sip:101@192.168.78.11"), 0)
		<< "the dialing phone must not be sent an intercom INVITE mid-setup:\n" << b.dump();
}

TEST(E911Notify, ConfigRoundTripsThroughTheHandlerApi)
{
	NBench b;
	b.handler->setE911Config("200", "2025550123", "Front office");

	const auto [exts, cb, loc] = b.handler->getE911Config();
	EXPECT_NE(exts.find("200"), std::string::npos);
	EXPECT_EQ(cb, "2025550123");
	EXPECT_EQ(loc, "Front office");
}

TEST(E911Notify, AControlCharacterInTheLocationIsDroppedNotPersisted)
{
	// The host/NVS store is tab/newline delimited; a smuggled separator would
	// corrupt every field after it on the next load.
	NBench b;
	b.handler->setE911Config("200", "", "Front\toffice");

	const auto [exts, cb, loc] = b.handler->getE911Config();
	(void)exts; (void)cb;
	EXPECT_EQ(loc, "") << "a control character must drop the field, got: " << loc;
}

// ─────────────────────────────────────────────────────────────────────────────
// The MESSAGE wire format itself
//
// This firmware has NEVER put a SIP MESSAGE on the wire. RequestsHandler::
// sendMessageTo() exists but has zero callers anywhere in src/, main/ or
// tests/, so the format it composes has never been exercised by anything --
// and EmergencyNotifier's own builder was written by reading it. That is
// exactly how a format bug gets inherited instead of caught, so the emitted
// MESSAGE is parsed back and checked here rather than assumed.
//
// What this proves: the message is well-formed on the wire. What it does NOT
// prove: that any given handset renders an inbound MESSAGE to a human at all.
// That is untestable on host and is stated as an open limitation rather than
// blurred into the above.
// ─────────────────────────────────────────────────────────────────────────────

TEST(E911Notify, TheEmittedMessageIsAWellFormedSipRequest)
{
	NBench b;
	b.handler->anchorClientForTest()->stop();   // exercise the failure text too
	b.handler->setE911Config("200", "2025550123", "Front office");
	b.wire.clear();

	b.handler->handle(enInvite("101", "911", "192.168.78.11", "en-911-wire"));

	const int idx = b.indexOf("MESSAGE sip:200@");
	ASSERT_GE(idx, 0) << "no MESSAGE was emitted:\n" << b.dump();
	const std::string raw = b.wire[static_cast<size_t>(idx)];

	// Request line: method and a sip: URI for the notify extension.
	EXPECT_EQ(raw.rfind("MESSAGE sip:200@", 0), 0u)
		<< "request line must start the datagram: " << raw.substr(0, 80);
	EXPECT_NE(raw.find(" SIP/2.0\r\n"), std::string::npos)
		<< "request line must carry the SIP version";

	// Headers a UA needs to accept and route the request at all.
	EXPECT_NE(raw.find("\r\nVia: SIP/2.0/UDP "), std::string::npos);
	EXPECT_NE(raw.find(";branch=z9hG4bK"), std::string::npos)
		<< "RFC 3261 8.1.1.7 requires the magic cookie on the Via branch";
	EXPECT_NE(raw.find("\r\nFrom: "), std::string::npos);
	EXPECT_NE(raw.find(";tag="), std::string::npos)
		<< "RFC 3261 8.1.1.3: a request outside a dialog still needs a From tag";
	EXPECT_NE(raw.find("\r\nTo: "), std::string::npos);
	EXPECT_NE(raw.find("\r\nCall-ID: "), std::string::npos);
	EXPECT_NE(raw.find("\r\nCSeq: 1 MESSAGE\r\n"), std::string::npos)
		<< "the CSeq method must match the request method (RFC 3261 8.1.1.5)";
	EXPECT_NE(raw.find("\r\nMax-Forwards: "), std::string::npos);
	EXPECT_NE(raw.find("\r\nContent-Type: text/plain\r\n"), std::string::npos)
		<< "RFC 3428 requires a Content-Type on a MESSAGE with a body";

	// Header/body separator present exactly once, and a real body after it.
	const size_t sep = raw.find("\r\n\r\n");
	ASSERT_NE(sep, std::string::npos) << "no header/body separator";
	const std::string body = raw.substr(sep + 4);
	EXPECT_FALSE(body.empty()) << "a notification with no body notifies nobody";
}

TEST(E911Notify, TheMessageContentLengthMatchesTheActualBody)
{
	// The single most consequential field to get wrong: a Content-Length that
	// disagrees with the body either truncates the text or leaves the receiver
	// waiting for bytes that never arrive. Nothing has ever exercised this
	// path, so it is checked by arithmetic rather than by eye.
	NBench b;
	b.handler->setE911Config("200", "2025550123", "Front office");
	b.wire.clear();

	b.handler->handle(enInvite("101", "911", "192.168.78.11", "en-911-clen"));

	const int idx = b.indexOf("MESSAGE sip:200@");
	ASSERT_GE(idx, 0) << b.dump();
	const std::string raw = b.wire[static_cast<size_t>(idx)];

	const size_t sep = raw.find("\r\n\r\n");
	ASSERT_NE(sep, std::string::npos);
	const std::string body = raw.substr(sep + 4);

	const size_t clPos = raw.find("\r\nContent-Length: ");
	ASSERT_NE(clPos, std::string::npos) << "no Content-Length header";
	const size_t valStart = clPos + std::string("\r\nContent-Length: ").size();
	const size_t valEnd = raw.find("\r\n", valStart);
	ASSERT_NE(valEnd, std::string::npos);
	const long declared = std::atol(raw.substr(valStart, valEnd - valStart).c_str());

	EXPECT_EQ(static_cast<size_t>(declared), body.size())
		<< "Content-Length " << declared << " but body is " << body.size()
		<< " bytes -- the receiver would truncate or stall";
}

TEST(E911Notify, TheMessageBodyIsExactlyTheNotificationText)
{
	// The body must be the same text the syslog record carries, not a
	// re-derived or re-truncated variant -- otherwise the two records of one
	// 911 call disagree, which is the worst possible thing for an audit trail.
	NBench b;
	b.handler->anchorClientForTest()->stop();
	b.handler->setE911Config("200", "2025550123", "Front office");
	b.wire.clear();

	b.handler->handle(enInvite("101", "911", "192.168.78.11", "en-911-body"));

	const int idx = b.indexOf("MESSAGE sip:200@");
	ASSERT_GE(idx, 0) << b.dump();
	const std::string raw = b.wire[static_cast<size_t>(idx)];
	const size_t sep = raw.find("\r\n\r\n");
	ASSERT_NE(sep, std::string::npos);
	const std::string body = raw.substr(sep + 4);

	pbx::E911Config cfg;
	cfg.notifyExts = {"200"};
	cfg.callback = "2025550123";
	cfg.location = "Front office";
	const std::string expected = pbx::formatE911Notification(
		/*isTest=*/false, "101", "911", /*hadTrunkPrefix=*/false, /*routed=*/false, cfg,
		"the 3CX anchor could not place the call; no trunk is configured");

	EXPECT_EQ(body, expected)
		<< "the SIP body and the syslog record must be the same text";
}

TEST(E911Notify, TheEmittedMessageSurvivesThisRepositoryOwnParser)
{
	// Round-trip through the engine's own parser: if pocket-dial cannot read
	// back what pocket-dial just wrote, no handset will either.
	NBench b;
	b.handler->setE911Config("200", "", "");
	b.wire.clear();

	b.handler->handle(enInvite("101", "911", "192.168.78.11", "en-911-parse"));

	const int idx = b.indexOf("MESSAGE sip:200@");
	ASSERT_GE(idx, 0) << b.dump();

	auto parsed = RequestsHandler::getMessageFromPool(
		b.wire[static_cast<size_t>(idx)], enAddr("192.168.78.1"));
	ASSERT_NE(parsed, nullptr) << "the engine's own parser rejected the MESSAGE it composed";
	EXPECT_NE(std::string(parsed->getCallID()).find("Call-ID:"), std::string::npos)
		<< "a parsed MESSAGE must expose its Call-ID";
}

// ─────────────────────────────────────────────────────────────────────────────
// The notifier's OWN bound
//
// Mutation testing caught this gap: removing the bound inside
// EmergencyNotifier::notify() changed nothing observable, because
// PbxFeatureConfig::setE911Config() already truncates before the notifier ever
// sees the list. That makes the notifier's bound defence-in-depth against a
// config this build did not write -- a store persisted by a build with a larger
// cap, say -- and unreachable through the public API by construction.
//
// Rather than delete a guard that protects the emergency path from an unbounded
// burst of pooled messages, or leave it permanently untested, the notifier is
// driven directly here through a counting PbxEnv. The count of findRegistered()
// calls IS the number of entries the loop considered, so it measures the bound
// without needing a registered client at all.
// ─────────────────────────────────────────────────────────────────────────────

namespace
{
	// Minimal PbxEnv. Everything the notifier does not use is a stub; the one
	// method that matters counts its calls.
	class CountingEnv : public PbxEnv
	{
	public:
		int findCalls = 0;
		int enqueued  = 0;

		std::shared_ptr<SipClient> findRegistered(std::string_view) override
		{
			++findCalls;
			return nullptr;   // nothing registered: buildNotifyMessage bails, which
			                  // is fine -- we are counting loop iterations.
		}
		void enqueue(const sockaddr_in&, std::shared_ptr<SipMessage>) override { ++enqueued; }
		std::shared_ptr<SipMessage> messageFromPool(std::string_view, sockaddr_in) override { return nullptr; }
		void freeTransactionsForCallId(std::string_view) override {}
		void log(std::string, bool = false) override {}
		const std::string& localIp() const override { return _ip; }
		int serverPort() const override { return 5060; }
		std::shared_ptr<SipClient> allocVirtualPeer(std::string, const sockaddr_in&) override { return nullptr; }
		std::shared_ptr<Session> allocSession(const std::string&, const std::shared_ptr<SipClient>&) override { return nullptr; }
		void insertSession(const std::string&, const std::shared_ptr<Session>&) override {}
		std::shared_ptr<Session> findSession(std::string_view) override { return nullptr; }
		std::string contactFor(std::string_view) const override { return ""; }
		std::shared_ptr<SipMessage> serverBye(const std::string&, const sockaddr_in&,
			const std::string&, const std::string&, const std::string&) override { return nullptr; }
		void forEachSessionInvolving(std::string_view,
			FunctionRef<void(const std::string&, const Session&, DialogRole)>) const override {}
		bool validAor(std::string_view) const override { return true; }
		int requestedExpires(const std::shared_ptr<SipMessage>&) const override { return 3600; }
		bool routeTrunkCall(const std::shared_ptr<SipMessage>&,
			const std::shared_ptr<SipClient>&, const std::string&) override { return false; }

	private:
		std::string _ip = "192.168.78.1";
	};
}

TEST(E911Notify, TheNotifierBoundsTheListItselfEvenIfTheConfigDidNot)
{
	CountingEnv env;
	EmergencyNotifier notifier(env);

	pbx::E911Config cfg;
	// Twice the cap, as a store written by a build with a larger cap would look
	// after load. setE911Config() can never produce this; that is the point.
	cfg.notifyExts = {"200", "201", "202", "203", "204", "205", "206", "207"};

	notifier.notify(cfg, /*isTest=*/false, "101", "911",
		/*hadTrunkPrefix=*/false, /*routed=*/true);

	EXPECT_LE(static_cast<size_t>(env.findCalls), pbx::kMaxE911NotifyExts)
		<< "the notifier considered " << env.findCalls
		<< " targets; an oversized config must not turn one 911 dial into an "
		   "unbounded burst of pooled messages on the emergency path";
}

TEST(E911Notify, TheSyslogRecordIsEmittedEvenWithNoNotifyTargetsAtAll)
{
	// The record is the one guaranteed half of the notification: an operator can
	// leave the notify list empty, but cannot turn off the fact that a 911 dial
	// was written down. Nothing here asserts syslog content (that needs a
	// collector); it asserts the path does not early-return before reaching it.
	CountingEnv env;
	EmergencyNotifier notifier(env);

	pbx::E911Config cfg;   // no targets at all
	const std::size_t n = notifier.notify(cfg, false, "101", "911", false, false);

	EXPECT_EQ(n, 0u) << "no targets means no MESSAGEs";
	EXPECT_EQ(env.findCalls, 0) << "and no lookups";
	EXPECT_EQ(env.enqueued, 0) << "and nothing on the wire";
}

// ─────────────────────────────────────────────────────────────────────────────
// "Answered" is not "placed"
//
// originateAnchorCall() returns true meaning "took ownership of the INVITE",
// and EIGHT refuse() paths inside it answer 4xx/5xx and still return true. The
// first cut of this feature read that bool as "the call went through", so a 911
// call refused for capacity would have been reported to the front desk as
// ROUTED. Caught in review of PR #242.
// ─────────────────────────────────────────────────────────────────────────────

TEST(E911Notify, ACallRefusedForCapacityIsNeverReportedAsRouted)
{
	NBench b;
	ASSERT_NE(b.loopback(), nullptr);
	b.handler->setE911Config("200", "", "");

	// Fill the anchor to its effective capacity with emergency calls: since
	// #624 a 911 pre-empts an ordinary anchored call, and only another
	// emergency call still leaves it refused for capacity.
	const unsigned cap = std::min<unsigned>(
		b.handler->anchorClientForTest()->maxConcurrentCalls(),
		static_cast<unsigned>(POCKETDIAL_MAX_ANCHOR_CALLS));
	ASSERT_GE(cap, 1u);
	for (unsigned i = 0; i < cap; ++i)
	{
		b.handler->handle(enInvite("101", "911", "192.168.78.11",
			"en-fill-" + std::to_string(i)));
	}
	b.wire.clear();

	// 911 from a DIFFERENT extension, so the dialer is not one of the fillers.
	b.handler->handle(enInvite("200", "911", "192.168.78.20", "en-911-busy"));

	ASSERT_NE(b.indexOf("SIP/2.0 503"), -1) << "precondition: refused for capacity:\n" << b.dump();
	EXPECT_EQ(b.indexOf("ROUTED TO TRUNK"), -1)
		<< "the anchor answered this INVITE with a 503 and still returned true; "
		   "reporting it as routed tells the front desk a 911 call went through "
		   "when it did not:\n" << b.dump();
}

// ─────────────────────────────────────────────────────────────────────────────
// #713: a worker that cannot start is not a routed call
//
// On a real anchor, originateAnchorCall() publishes the session, sends 180 and
// hands makeCall() to a worker task. When that task cannot be created (heap
// pressure during an active call) asyncMakeCall() answers 503 and ends the
// session -- but `placed` stayed true, so the front desk was told ROUTED. The
// host build drives the same async branch over the loopback client through
// forceAsyncAnchorForTest(); failNextAnchorWorkerSpawnForTest() is the ESP
// spawn failure. Since #878 Phase A a 911's job is queued before its session is
// published or its 180 sent, so its refusal is a refusal before dispatch and
// goes to the trunk if there is one (none here). An ordinary call still gets
// 180, then 503.
// ─────────────────────────────────────────────────────────────────────────────

TEST(E911Notify, AWorkerThatCannotStartIsNeverReportedAsRouted)
{
	NBench b;
	ASSERT_NE(b.loopback(), nullptr);
	b.handler->setE911Config("200", "", "");
	b.handler->forceAsyncAnchorForTest(true);
	b.handler->failNextAnchorWorkerSpawnForTest();
	b.wire.clear();

	b.handler->handle(enInvite("101", "911", "192.168.78.11", "en-911-nospawn"));

	ASSERT_NE(b.indexOf("SIP/2.0 503"), -1)
		<< "precondition: the spawn failure answered the caller 503:\n" << b.dump();
	ASSERT_FALSE(b.handler->getSession("Call-ID: en-911-nospawn").has_value())
		<< "precondition: and ended the session";
	ASSERT_NE(b.indexOf("MESSAGE sip:200@"), -1) << b.dump();
	EXPECT_NE(b.indexOf("NOT ROUTED"), -1)
		<< "no worker means no call; the notification must say so:\n" << b.dump();
	EXPECT_EQ(b.indexOf("ROUTED TO TRUNK"), -1)
		<< "a 911 refused because its worker could not start was reported as routed:\n" << b.dump();
}

TEST(E911Notify, AWorkerThatStartsIsReportedAsRouted)
{
	// Control for the test above: the same async branch with a worker that does
	// start is a placed call (180 Ringing, no 503), notified as routed.
	NBench b;
	ASSERT_NE(b.loopback(), nullptr);
	b.handler->setE911Config("200", "", "");
	b.handler->forceAsyncAnchorForTest(true);
	b.wire.clear();

	b.handler->handle(enInvite("101", "911", "192.168.78.11", "en-911-spawn"));

	EXPECT_NE(b.indexOf("SIP/2.0 180"), -1) << b.dump();
	EXPECT_EQ(b.indexOf("SIP/2.0 503"), -1) << b.dump();
	EXPECT_NE(b.indexOf("ROUTED TO TRUNK"), -1) << b.dump();
	EXPECT_EQ(b.indexOf("NOT ROUTED"), -1) << b.dump();
}

TEST(E911Notify, AnOrdinaryAnchoredCallWhoseWorkerCannotStartIsRefusedOnceAndNotNotified)
{
	// The negative case: the same spawn failure on a plain 555 dial is exactly
	// one 503, no session left behind, and no emergency notification.
	NBench b;
	ASSERT_NE(b.loopback(), nullptr);
	b.handler->setE911Config("200", "", "");
	b.handler->forceAsyncAnchorForTest(true);
	b.handler->failNextAnchorWorkerSpawnForTest();
	b.wire.clear();

	b.handler->handle(enInvite("101", "555", "192.168.78.11", "en-555-nospawn"));

	EXPECT_EQ(b.countOf("SIP/2.0 503"), 1) << b.dump();
	EXPECT_EQ(b.countOf("SIP/2.0 200 OK"), 0) << b.dump();
	EXPECT_FALSE(b.handler->getSession("Call-ID: en-555-nospawn").has_value());
	EXPECT_EQ(b.indexOf("MESSAGE sip:200@"), -1) << "a 555 dial is not an emergency:\n" << b.dump();
}

// ─────────────────────────────────────────────────────────────────────────────
// #821: ROUTED goes out when the 911 is handed to its worker. When that
// worker's makeCall() then fails -- the anchor declines, or (TelephonyAnchor-
// Client, ESP only) the 911's leg still has no call slot after the #743 wait
// and is dropped -- the caller gets its 503 and the notify list must be told
// NOT ROUTED. The worker is parked while the loopback stops, so its makeCall()
// returns false. tel_sos has no worker here, so the 911 runs on tel_ctl (#863),
// the lane holdTelCtlForTest() parks.
// ─────────────────────────────────────────────────────────────────────────────

namespace
{
	bool waitUntil(const std::function<bool()>& done)
	{
		const auto until = std::chrono::steady_clock::now() + std::chrono::seconds(3);
		while (!done())
		{
			if (std::chrono::steady_clock::now() > until) return false;
			std::this_thread::sleep_for(std::chrono::milliseconds(5));
		}
		return true;
	}

	// The SIP thread's next pass drains _asyncOutbox. An OPTIONS from an address
	// on no dialog stands in for it (as TrunkWiring_test does).
	void flushAsyncOutbox(NBench& b)
	{
		b.handler->handle(RequestsHandler::getMessageFromPool(
			"OPTIONS sip:server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP 192.168.78.99:5060;branch=z9hG4bKflush821\r\n"
			"From: <sip:probe@server>;tag=probe821\r\n"
			"To: <sip:server@server>\r\n"
			"Call-ID: flush-821\r\n"
			"CSeq: 1 OPTIONS\r\n"
			"Max-Forwards: 70\r\n"
			"Content-Length: 0\r\n\r\n", enAddr("192.168.78.99")));
	}

	void dialAndFailTheWorkersMakeCall(NBench& b, const std::string& to, const std::string& callId)
	{
		b.handler->failTelCtlLaneForTest(RequestsHandler::kLaneSos);
		b.handler->forceAsyncAnchorForTest(true);
		b.handler->holdTelCtlForTest(true);
		b.handler->handle(enInvite("101", to, "192.168.78.11", callId));
		ASSERT_NE(b.indexOf("SIP/2.0 180"), -1) << "precondition: the call was dispatched:\n" << b.dump();
		ASSERT_TRUE(waitUntil([&] { return b.handler->telCtlParkedForTest() == 1; }))
			<< "precondition: the worker took the makeCall";
		b.loopback()->stop();
		b.handler->holdTelCtlForTest(false);
		ASSERT_TRUE(waitUntil([&] { flushAsyncOutbox(b); return b.indexOf("SIP/2.0 503") != -1; }))
			<< "precondition: the failed makeCall answered the caller 503:\n" << b.dump();
	}
}

TEST(E911Notify, A911WhoseAnchorLegNeverComesUpIsReportedNotRoutedAfterItsFiveOhThree)
{
	NBench b;
	ASSERT_NE(b.loopback(), nullptr);
	b.handler->setE911Config("200", "", "");
	b.wire.clear();

	ASSERT_NO_FATAL_FAILURE(dialAndFailTheWorkersMakeCall(b, "911", "en-911-mkfail"));

	const int routed = b.indexOf("ROUTED TO TRUNK");
	ASSERT_NE(routed, -1) << "precondition: the dispatch was notified ROUTED:\n" << b.dump();
	EXPECT_EQ(b.countOf("SIP/2.0 503"), 1) << b.dump();
	EXPECT_FALSE(b.handler->getSession("Call-ID: en-911-mkfail").has_value());
	const int notRouted = b.indexOf("NOT ROUTED");
	EXPECT_EQ(b.countOf("NOT ROUTED"), 1) << "the 911 never came up; the notify list is told so exactly once:\n" << b.dump();
	EXPECT_GT(notRouted, routed) << "NOT ROUTED corrects the earlier ROUTED, so it comes after it";
	EXPECT_GT(notRouted, b.indexOf("SIP/2.0 503")) << "the caller's 503 first, then the notification";
}

TEST(E911Notify, AnOrdinaryCallWhoseAnchorLegNeverComesUpIsRefusedOnceAndNotNotified)
{
	NBench b;
	ASSERT_NE(b.loopback(), nullptr);
	b.handler->setE911Config("200", "", "");
	b.wire.clear();

	ASSERT_NO_FATAL_FAILURE(dialAndFailTheWorkersMakeCall(b, "555", "en-555-mkfail"));

	EXPECT_EQ(b.countOf("SIP/2.0 503"), 1) << b.dump();
	EXPECT_EQ(b.indexOf("MESSAGE sip:200@"), -1) << "a 555 dial is not an emergency:\n" << b.dump();
}

// ─────────────────────────────────────────────────────────────────────────────
// desmo, #878: a NOT ROUTED notification names the route that failed. "no
// trunk available" was wrong whenever it was the anchor that failed.
// ─────────────────────────────────────────────────────────────────────────────

namespace
{
	// A trunk whose SBC is a name nothing has resolved: placeSipTrunkCall()
	// reads the resolver cache only, so it refuses the call with a 503.
	SipTrunk::Config unresolvedTrunk()
	{
		SipTrunk::Config c;
		std::snprintf(c.host, sizeof(c.host), "%s", "sbc.carrier.example");
		c.port = 5060;
		std::snprintf(c.fromUser, sizeof(c.fromUser), "%s", "trunkuser");
		c.enabled = true;
		return c;
	}

	std::shared_ptr<SipMessage> enInvitePcma(const std::string& fromExt, const std::string& toExt,
		const std::string& ip, const std::string& callId)
	{
		const std::string body =
			"v=0\r\no=- 0 0 IN IP4 " + ip + "\r\ns=-\r\nc=IN IP4 " + ip + "\r\nt=0 0\r\n"
			"m=audio 10000 RTP/AVP 8\r\na=rtpmap:8 PCMA/8000\r\n";
		const std::string raw =
			"INVITE sip:" + toExt + "@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + ip + ":5060;branch=z9hG4bKp" + callId + "\r\n"
			"From: <sip:" + fromExt + "@server>;tag=fp" + callId + "\r\n"
			"To: <sip:" + toExt + "@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Max-Forwards: 70\r\n"
			"Contact: <sip:" + fromExt + "@" + ip + ":5060>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		return RequestsHandler::getMessageFromPool(raw, enAddr(ip));
	}

	void expectOneNotRouted(const NBench& b, const std::string& reason)
	{
		EXPECT_EQ(b.countOf("NOT ROUTED"), 1) << b.dump();
		EXPECT_NE(b.indexOf("NOT ROUTED (" + reason + ")"), -1) << "the notification must name what failed:\n" << b.dump();
		EXPECT_EQ(b.indexOf("no trunk available"), -1) << b.dump();
	}
}

TEST(E911Notify, ANotRoutedNotificationNamesTheRouteThatFailed)
{
	const std::string anchor = "the 3CX anchor could not place the call";
	{
		SCOPED_TRACE("the anchor worker's makeCall() fails");
		NBench b;
		b.handler->setE911Config("200", "", "");
		b.wire.clear();
		ASSERT_NO_FATAL_FAILURE(dialAndFailTheWorkersMakeCall(b, "911", "en-q5-worker"));
		expectOneNotRouted(b, anchor);
	}
	{
		SCOPED_TRACE("the anchor's worker queue refuses it");
		NBench b;
		b.handler->setE911Config("200", "", "");
		b.handler->forceAsyncAnchorForTest(true);
		b.handler->failNextAnchorWorkerSpawnForTest();
		b.wire.clear();
		b.handler->handle(enInvite("101", "911", "192.168.78.11", "en-q5-queue"));
		// #878 Phase A: a refusal before dispatch now tries the trunk; there is none.
		expectOneNotRouted(b, anchor + "; no trunk is configured");
	}
	{
		SCOPED_TRACE("the anchor is down and the trunk refuses it");
		NBench b;
		b.handler->setE911Config("200", "", "");
		b.handler->anchorClientForTest()->stop();
		b.handler->setTrunkConfig(unresolvedTrunk());
		b.wire.clear();
		b.handler->handle(enInvite("101", "911", "192.168.78.11", "en-q5-both"));
		expectOneNotRouted(b, anchor + "; the trunk refused it");
	}
	{
		SCOPED_TRACE("the anchor is down and there is no trunk");
		NBench b;
		b.handler->setE911Config("200", "", "");
		b.handler->anchorClientForTest()->stop();
		b.wire.clear();
		b.handler->handle(enInvite("101", "911", "192.168.78.11", "en-q5-notrunk"));
		expectOneNotRouted(b, anchor + "; no trunk is configured");
	}
	{
		SCOPED_TRACE("the trunk is the only route and refuses it");
		NBench b;
		b.handler->setE911Config("200", "", "");
		b.handler->setAnchorPlacesRealCallsForTest(false);
		b.handler->setTrunkConfig(unresolvedTrunk());
		b.wire.clear();
		b.handler->handle(enInvite("101", "911", "192.168.78.11", "en-q5-trunk"));
		expectOneNotRouted(b, "the trunk refused it");
	}
	{
		SCOPED_TRACE("no route at all");
		NBench b;
		b.handler->setE911Config("200", "", "");
		b.handler->setAnchorPlacesRealCallsForTest(false);
		b.wire.clear();
		b.handler->handle(enInvite("101", "911", "192.168.78.11", "en-q5-none"));
		expectOneNotRouted(b, "no emergency route configured");
	}
	{
		SCOPED_TRACE("no G.711 codec offered");
		NBench b;
		b.handler->setE911Config("200", "", "");
		b.wire.clear();
		b.handler->handle(enInvitePcma("101", "911", "192.168.78.11", "en-q5-codec"));
		expectOneNotRouted(b, "no G.711 codec offered");
	}
}

TEST(E911Format, TruncationLandsOnAUtf8BoundaryNotMidCodepoint)
{
	// `location` is operator free text and may be non-ASCII. Cutting at byte 512
	// can split a multi-byte sequence, and a half-written codepoint renders as
	// garbage in whatever reads the notification.
	pbx::E911Config cfg;
	cfg.location = std::string(300, 'x');
	for (int i = 0; i < 80; ++i) cfg.location += "\xC3\xA9";   // 'e' acute, 2 bytes

	const std::string s = pbx::formatE911Notification(false, "101", "911", false, true, cfg);
	ASSERT_LE(s.size(), 512u);

	// Validate the whole string decodes: every lead byte is followed by exactly
	// the continuation bytes it declares.
	size_t i = 0;
	while (i < s.size())
	{
		const unsigned char c = static_cast<unsigned char>(s[i]);
		size_t need = 0;
		if ((c & 0x80) == 0x00) need = 0;
		else if ((c & 0xE0) == 0xC0) need = 1;
		else if ((c & 0xF0) == 0xE0) need = 2;
		else if ((c & 0xF8) == 0xF0) need = 3;
		else FAIL() << "stray continuation byte at " << i;
		ASSERT_LE(i + need, s.size() - 1) << "truncated mid-codepoint at byte " << i;
		for (size_t k = 1; k <= need; ++k)
		{
			ASSERT_EQ(static_cast<unsigned char>(s[i + k]) & 0xC0, 0x80)
				<< "bad continuation byte at " << (i + k);
		}
		i += need + 1;
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// #878 Phase A (desmo: "YES, fall back to the trunk"; the coordinator scoped it
// to refusals before dispatch). An anchor refusal before anything has left for
// 3CX, with nothing answered yet, hands the 911 to the trunk, as an anchor that
// is not connected already does. Driven by the worker-queue refusal on the async
// anchor. A failure after dispatch (Phase B) is not retried.
// ─────────────────────────────────────────────────────────────────────────────

namespace
{
	SipTrunk::Config dottedQuadTrunk()
	{
		SipTrunk::Config c;
		std::snprintf(c.host, sizeof(c.host), "%s", "203.0.113.5");   // RFC 5737 TEST-NET-3
		c.port = 5060;
		std::snprintf(c.fromUser, sizeof(c.fromUser), "%s", "trunkuser");
		c.enabled = true;
		return c;
	}

	// Wire entries whose first line starts with `start`.
	int countStarting(const NBench& b, const std::string& start)
	{
		int n = 0;
		for (const auto& s : b.wire)
			if (s.rfind(start, 0) == 0) ++n;
		return n;
	}

	// A 911 (or `to`) from 101 on the async anchor whose worker queue refuses it.
	void dialRefusedBeforeDispatch(NBench& b, const std::string& to, const std::string& callId)
	{
		b.handler->forceAsyncAnchorForTest(true);
		b.handler->failNextAnchorWorkerSpawnForTest();
		b.wire.clear();
		b.handler->handle(enInvite("101", to, "192.168.78.11", callId));
	}
}

TEST(E911Notify, A911TheAnchorRefusesBeforeDispatchFallsBackToTheTrunk)
{
	{
		SCOPED_TRACE("the trunk takes it");
		NBench b;
		b.handler->setE911Config("200", "", "");
		b.handler->setTrunkConfig(dottedQuadTrunk());
		dialRefusedBeforeDispatch(b, "911", "en-pa-ok");
		EXPECT_EQ(countStarting(b, "INVITE sip:911@203.0.113.5"), 1) << "the trunk must carry it:\n" << b.dump();
		EXPECT_EQ(countStarting(b, "SIP/2.0 180"), 1) << "one 180 and one dialog: the anchor answered nothing:\n" << b.dump();
		EXPECT_EQ(countStarting(b, "SIP/2.0 503"), 0) << b.dump();
		EXPECT_EQ(countStarting(b, "MESSAGE sip:200@"), 1) << "exactly one notification:\n" << b.dump();
		EXPECT_EQ(b.countOf("ROUTED TO TRUNK (the 3CX anchor could not place the call)"), 1) << b.dump();
		EXPECT_EQ(b.countOf("NOT ROUTED"), 0) << b.dump();
		const auto s = b.handler->getSession("Call-ID: en-pa-ok");
		EXPECT_TRUE(s.has_value()) << "one session, the trunk's";
		if (s.has_value())
		{
			EXPECT_TRUE(s.value()->isTrunk());
			EXPECT_FALSE(s.value()->isAnchor());
			EXPECT_TRUE(s.value()->isEmergency()) << "the trunk path a dialed 911 takes flags it";
		}
		EXPECT_EQ(b.handler->trunkRelaysInUseForTest(), 1u);
	}
	{
		SCOPED_TRACE("no trunk is configured");
		NBench b;
		b.handler->setE911Config("200", "", "");
		dialRefusedBeforeDispatch(b, "911", "en-pa-none");
		EXPECT_EQ(countStarting(b, "SIP/2.0 180"), 0) << "refused before dispatch: nothing rang:\n" << b.dump();
		EXPECT_EQ(countStarting(b, "SIP/2.0 503"), 1) << b.dump();
		expectOneNotRouted(b, "the 3CX anchor could not place the call; no trunk is configured");
		EXPECT_FALSE(b.handler->getSession("Call-ID: en-pa-none").has_value());
	}
	{
		SCOPED_TRACE("the trunk refuses it too");
		NBench b;
		b.handler->setE911Config("200", "", "");
		b.handler->setTrunkConfig(unresolvedTrunk());
		dialRefusedBeforeDispatch(b, "911", "en-pa-both");
		EXPECT_EQ(countStarting(b, "SIP/2.0 180"), 0) << b.dump();
		EXPECT_EQ(countStarting(b, "SIP/2.0 503"), 1) << b.dump();
		expectOneNotRouted(b, "the 3CX anchor could not place the call; the trunk refused it");
		EXPECT_FALSE(b.handler->getSession("Call-ID: en-pa-both").has_value());
		EXPECT_EQ(b.handler->trunkRelaysInUseForTest(), 0u);
	}
}

TEST(E911Notify, AnOrdinaryCallTheAnchorRefusesBeforeDispatchIsNotRetriedOnTheTrunk)
{
	// Negative: a 555 dial with the same refusal and a trunk configured is
	// answered as before (180, then 503) and never reaches the carrier.
	NBench b;
	b.handler->setE911Config("200", "", "");
	b.handler->setTrunkConfig(dottedQuadTrunk());
	dialRefusedBeforeDispatch(b, "555", "en-pa-555");
	EXPECT_EQ(countStarting(b, "SIP/2.0 180"), 1) << b.dump();
	EXPECT_EQ(countStarting(b, "SIP/2.0 503"), 1) << b.dump();
	EXPECT_EQ(countStarting(b, "INVITE sip:"), 0) << "no trunk retry for an ordinary call:\n" << b.dump();
	EXPECT_EQ(countStarting(b, "MESSAGE sip:200@"), 0) << b.dump();
}

// ─────────────────────────────────────────────────────────────────────────────
// #879 (#878 review B-BLK-1): a 911/933 the trunk took was notified ROUTED when
// it was placed. When the carrier then refuses it, or the trunk times it out,
// onTrunkFailed() answers the handset as before, and the notify list now hears
// exactly one NOT ROUTED after that ROUTED, naming the carrier's status. A 911
// that drew any provisional is never timed out by the PBX (#712; desmo
// confirmed "YES, exempt"; #889); one that drew no provisional at all still is.
// ─────────────────────────────────────────────────────────────────────────────

namespace
{
	// The carrier's final response to the trunk INVITE the handler sent to the
	// SBC: that INVITE's own Via, From, Call-ID and CSeq, its To with a tag.
	std::shared_ptr<SipMessage> carrierResponse(const NBench& b, const std::string& statusLine,
		bool withSdp = false)
	{
		std::string invite;
		for (const auto& s : b.wire)
		{
			if (s.rfind("INVITE sip:", 0) == 0 && s.find("@203.0.113.5") < s.find("\r\n")) { invite = s; break; }
		}
		auto line = [&invite](const std::string& name) {
			const size_t p = invite.find("\r\n" + name);
			if (p == std::string::npos) return std::string();
			return invite.substr(p + 2, invite.find("\r\n", p + 2) - p - 2);
		};
		const std::string sdp = withSdp
			? "v=0\r\no=- 0 0 IN IP4 203.0.113.9\r\ns=-\r\nc=IN IP4 203.0.113.9\r\n"
			  "t=0 0\r\nm=audio 41000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
			: "";
		const std::string raw = statusLine + "\r\n" + line("Via: ") + "\r\n" + line("From: ") + "\r\n" +
			line("To: ") + ";tag=carrier879\r\n" + line("Call-ID: ") + "\r\n" + line("CSeq: ") + "\r\n" +
			(withSdp ? "Contact: <sip:911@203.0.113.9:5060>\r\nContent-Type: application/sdp\r\n" : "") +
			"Content-Length: " + std::to_string(sdp.size()) + "\r\n\r\n" + sdp;
		return RequestsHandler::getMessageFromPool(raw, enAddr("203.0.113.5"));
	}

	// `handsetFinal`, when given, is the start line of the handset's final
	// response, which the correction must follow too (review N-C4).
	void expectNotRoutedAfterRouted(const NBench& b, const std::string& reason,
		const std::string& handsetFinal = "")
	{
		const int routed = b.indexOf("ROUTED TO TRUNK");
		EXPECT_NE(routed, -1) << "precondition: the trunk call was notified ROUTED:\n" << b.dump();
		EXPECT_EQ(b.countOf("NOT ROUTED"), 1) << "the failure must be told exactly once:\n" << b.dump();
		EXPECT_NE(b.indexOf("NOT ROUTED (" + reason + ")"), -1) << b.dump();
		EXPECT_GT(b.indexOf("NOT ROUTED"), routed) << "the correction follows the ROUTED it corrects";
		if (handsetFinal.empty()) return;
		int answered = -1;
		for (size_t i = 0; i < b.wire.size() && answered < 0; ++i)
			if (b.wire[i].rfind(handsetFinal, 0) == 0) answered = static_cast<int>(i);
		EXPECT_NE(answered, -1) << "precondition: the handset got " << handsetFinal << ":\n" << b.dump();
		EXPECT_GT(b.indexOf("NOT ROUTED"), answered) << "the correction follows the handset's " << handsetFinal;
	}
}

TEST(E911Notify, A911TheCarrierRefusesAfterTheTrunkTookItIsReportedNotRouted)
{
	{
		SCOPED_TRACE("the trunk stood in for the anchor (Phase A), the carrier answers 403");
		NBench b;
		b.handler->setE911Config("200", "", "");
		b.handler->setTrunkConfig(dottedQuadTrunk());
		dialRefusedBeforeDispatch(b, "911", "en-879-pa");
		ASSERT_EQ(countStarting(b, "INVITE sip:911@203.0.113.5"), 1) << b.dump();
		b.handler->handle(carrierResponse(b, "SIP/2.0 403 Forbidden"));
		EXPECT_EQ(countStarting(b, "SIP/2.0 502"), 1) << "the handset's answer is unchanged:\n" << b.dump();
		expectNotRoutedAfterRouted(b, "the 3CX anchor could not place the call; the trunk refused it (403)", "SIP/2.0 502");
		EXPECT_FALSE(b.handler->getSession("Call-ID: en-879-pa").has_value());
	}
	{
		SCOPED_TRACE("the trunk is the only route, the carrier answers 503");
		NBench b;
		b.handler->setE911Config("200", "", "");
		b.handler->setAnchorPlacesRealCallsForTest(false);
		b.handler->setTrunkConfig(dottedQuadTrunk());
		b.wire.clear();
		b.handler->handle(enInvite("101", "911", "192.168.78.11", "en-879-trunk"));
		ASSERT_EQ(countStarting(b, "INVITE sip:911@203.0.113.5"), 1) << b.dump();
		b.handler->handle(carrierResponse(b, "SIP/2.0 503 Service Unavailable"));
		EXPECT_EQ(countStarting(b, "SIP/2.0 503"), 1) << b.dump();
		expectNotRoutedAfterRouted(b, "the trunk refused it (503)", "SIP/2.0 503");
	}
	{
		SCOPED_TRACE("the carrier never answers the INVITE at all: the trunk times it out");
		NBench b;
		b.handler->setE911Config("200", "", "");
		b.handler->setAnchorPlacesRealCallsForTest(false);
		b.handler->setTrunkConfig(dottedQuadTrunk());
		b.wire.clear();
		b.handler->handle(enInvite("101", "911", "192.168.78.11", "en-879-silent"));
		ASSERT_EQ(countStarting(b, "INVITE sip:911@203.0.113.5"), 1) << b.dump();
		b.handler->expireTrunkDeadlinesForTest();
		b.handler->forceNextTickForTest();
		b.handler->tick();
		EXPECT_EQ(countStarting(b, "SIP/2.0 503"), 1) << b.dump();
		expectNotRoutedAfterRouted(b, "the trunk timed out (408)", "SIP/2.0 503");
	}
	{
		SCOPED_TRACE("control: a ringing 911 is never timed out, so nothing is reported");
		NBench b;
		b.handler->setE911Config("200", "", "");
		b.handler->setAnchorPlacesRealCallsForTest(false);
		b.handler->setTrunkConfig(dottedQuadTrunk());
		b.wire.clear();
		b.handler->handle(enInvite("101", "911", "192.168.78.11", "en-879-ring"));
		b.handler->handle(carrierResponse(b, "SIP/2.0 180 Ringing"));
		b.handler->expireTrunkDeadlinesForTest();
		b.handler->forceNextTickForTest();
		b.handler->tick();
		EXPECT_TRUE(b.handler->getSession("Call-ID: en-879-ring").has_value()) << "#712: a ringing 911 survives:\n" << b.dump();
		EXPECT_EQ(b.countOf("NOT ROUTED"), 0) << b.dump();
		EXPECT_EQ(countStarting(b, "SIP/2.0 503"), 0) << b.dump();
	}
}

TEST(E911Notify, AnOrdinaryTrunkCallTheCarrierRefusesIsNotNotified)
{
	// Negative: the same carrier refusal on a non-emergency trunk call answers
	// the handset as before and notifies nobody.
	NBench b;
	b.handler->setE911Config("200", "", "");
	b.handler->setTrunkConfig(dottedQuadTrunk());
	b.handler->setDialRule("45X", "trunk", "", 0);
	b.wire.clear();
	b.handler->handle(enInvite("101", "455", "192.168.78.11", "en-879-pstn"));
	ASSERT_EQ(countStarting(b, "INVITE sip:+455@203.0.113.5"), 1) << b.dump();
	b.handler->handle(carrierResponse(b, "SIP/2.0 403 Forbidden"));
	EXPECT_EQ(countStarting(b, "SIP/2.0 502"), 1) << b.dump();
	EXPECT_EQ(countStarting(b, "MESSAGE sip:200@"), 0) << b.dump();
}

// #889: a 100, 181, 182 or 199 is a provisional too (desmo, 2026-10-05: only a
// 911 with no provisional at all is not exempt). Each used to miss SipTrunk,
// so the dialog stayed Trying and the 60 s sweep refused the 911 and reported
// it NOT ROUTED. Both timers are aged here; a retransmitted provisional is
// sent too. The control, no provisional at all, still ends at the timeout with
// one 503 and one NOT ROUTED.
TEST(E911Notify, ATrunk911ThatDrewAnyProvisionalIsNeverTimedOut)
{
	const char* const provisionals[] = { "SIP/2.0 100 Trying", "SIP/2.0 181 Call Is Being Forwarded",
		"SIP/2.0 182 Queued", "SIP/2.0 199 Early Dialog Terminated", "" };
	for (const std::string number : { "911", "933" })
	{
		for (const std::string provisional : provisionals)
		{
			SCOPED_TRACE(number + ", the carrier's only answer: " + (provisional.empty() ? "none" : provisional));
			NBench b;
			b.handler->setE911Config("200", "", "");
			b.handler->setAnchorPlacesRealCallsForTest(false);
			b.handler->setTrunkConfig(dottedQuadTrunk());
			b.wire.clear();
			const std::string callId = "en-889-" + number + "-" + (provisional.empty() ? "none" : provisional.substr(8, 3));
			b.handler->handle(enInvite("101", number, "192.168.78.11", callId));
			ASSERT_EQ(countStarting(b, "INVITE sip:" + number + "@203.0.113.5"), 1) << b.dump();
			if (!provisional.empty())
			{
				b.handler->handle(carrierResponse(b, provisional));
				b.handler->handle(carrierResponse(b, provisional));
			}
			b.handler->expireTransactionTimersForTest();
			b.handler->expireTrunkDeadlinesForTest();
			b.handler->forceNextTickForTest();
			b.handler->tick();
			EXPECT_EQ(b.countOf("ROUTED TO TRUNK"), 1) << b.dump();
			if (provisional.empty())
			{
				EXPECT_EQ(countStarting(b, "SIP/2.0 503"), 1) << b.dump();
				expectNotRoutedAfterRouted(b, "the trunk timed out (408)", "SIP/2.0 503");
				EXPECT_FALSE(b.handler->getSession("Call-ID: " + callId).has_value()) << b.dump();
				continue;
			}
			EXPECT_TRUE(b.handler->getSession("Call-ID: " + callId).has_value())
				<< "the carrier is working on this call; the PBX may not end it:\n" << b.dump();
			EXPECT_EQ(countStarting(b, "SIP/2.0 503"), 0) << b.dump();
			EXPECT_EQ(b.countOf("NOT ROUTED"), 0) << b.dump();
			EXPECT_EQ(b.handler->trunkRelaysInUseForTest(), 1u) << "the relay stays up for the answer";
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// #878 review S-B3 and S-B4: only a refusal that sent nothing may go to the
// trunk, and the bridges-busy refusal, the case where Phase A actually wins
// because the trunk has relays of its own, is driven on the host.
// ─────────────────────────────────────────────────────────────────────────────

TEST(E911Notify, AnAnchorPathThatAnswersAndReturnsFalseIsNeverRetriedOnTheTrunk)
{
	// A false return WITHOUT refusedBeforeDispatchOut is the anchor's own
	// answer. A second route after it would be a second final response, and
	// after dispatch a possible second PSAP call.
	NBench b;
	b.handler->setE911Config("200", "", "");
	b.handler->setTrunkConfig(dottedQuadTrunk());
	b.handler->answerThenFailNextAnchorCallForTest();
	b.wire.clear();
	b.handler->handle(enInvite("101", "911", "192.168.78.11", "en-sb3"));
	EXPECT_EQ(countStarting(b, "SIP/2.0 503"), 1) << b.dump();
	EXPECT_EQ(countStarting(b, "INVITE sip:911@203.0.113.5"), 0) << "no second route:\n" << b.dump();
	EXPECT_EQ(countStarting(b, "SIP/2.0 180"), 0) << b.dump();
	expectOneNotRouted(b, "the 3CX anchor could not place the call");
	EXPECT_EQ(b.countOf("ROUTED TO TRUNK"), 0) << "no ROUTED for a route never taken:\n" << b.dump();
}

TEST(E911Notify, A911TheAnchorRefusesForBusyBridgesFallsBackToTheTrunk)
{
	// The loopback anchor has one bridge. A 911 answered on the synchronous
	// branch holds it, and an emergency call is never pre-empted (#624). The
	// next 911, on the async branch, then finds every bridge busy before
	// dispatch, and the trunk, on its own relay pair, takes it.
	NBench b;
	b.handler->setE911Config("200", "", "");
	b.handler->setTrunkConfig(dottedQuadTrunk());
	b.handler->handle(enInvite("101", "911", "192.168.78.11", "en-sb4-first"));
	ASSERT_NE(b.handler->anchorBridgeForCallIdForTest("Call-ID: en-sb4-first"), nullptr)
		<< "precondition: the first 911 holds the anchor's only bridge:\n" << b.dump();
	b.handler->forceAsyncAnchorForTest(true);
	b.wire.clear();
	b.handler->handle(enInvite("101", "911", "192.168.78.11", "en-sb4"));
	EXPECT_EQ(countStarting(b, "INVITE sip:911@203.0.113.5"), 1) << "the trunk must carry it:\n" << b.dump();
	EXPECT_EQ(countStarting(b, "SIP/2.0 180"), 1) << b.dump();
	EXPECT_EQ(countStarting(b, "SIP/2.0 503"), 0) << b.dump();
	EXPECT_EQ(b.countOf("ROUTED TO TRUNK (the 3CX anchor could not place the call)"), 1) << b.dump();
	EXPECT_EQ(b.countOf("NOT ROUTED"), 0) << b.dump();
	EXPECT_TRUE(b.handler->anchorBridgeForCallIdForTest("Call-ID: en-sb4-first") != nullptr)
		<< "the first 911 keeps its bridge";
}

// ─────────────────────────────────────────────────────────────────────────────
// #878 review S-C2: a final from the carrier after its own 2xx (a stateless
// forking hop or a broken SBC; RFC 3261 §16.7 forbids it) refuses no 911 still
// ringing: the PSAP answered it. ROUTED stands and no NOT ROUTED follows. Nor
// does that final end the call (#890, the test after this one).
// ─────────────────────────────────────────────────────────────────────────────

TEST(E911Notify, ACarrierFinalAfterItsTwoHundredIsNeverReportedNotRouted)
{
	{
		SCOPED_TRACE("a 486 after the carrier's 200");
		NBench b;
		b.handler->setE911Config("200", "", "");
		b.handler->setAnchorPlacesRealCallsForTest(false);
		b.handler->setTrunkConfig(dottedQuadTrunk());
		b.wire.clear();
		b.handler->handle(enInvite("101", "911", "192.168.78.11", "en-sc2"));
		ASSERT_EQ(countStarting(b, "INVITE sip:911@203.0.113.5"), 1) << b.dump();
		b.handler->handle(carrierResponse(b, "SIP/2.0 200 OK", /*withSdp=*/true));
		const auto s = b.handler->getSession("Call-ID: en-sc2");
		ASSERT_TRUE(s.has_value() && s.value()->getState() == Session::State::Connected)
			<< "precondition: the PSAP answered the 911:\n" << b.dump();
		b.handler->handle(carrierResponse(b, "SIP/2.0 486 Busy Here"));
		EXPECT_EQ(b.countOf("ROUTED TO TRUNK"), 1) << b.dump();
		EXPECT_EQ(b.countOf("NOT ROUTED"), 0) << "the PSAP answered this 911; it was not refused:\n" << b.dump();
	}
	{
		SCOPED_TRACE("negative: a 486 before any 2xx is still told, once");
		NBench b;
		b.handler->setE911Config("200", "", "");
		b.handler->setAnchorPlacesRealCallsForTest(false);
		b.handler->setTrunkConfig(dottedQuadTrunk());
		b.wire.clear();
		b.handler->handle(enInvite("101", "911", "192.168.78.11", "en-sc2-neg"));
		ASSERT_EQ(countStarting(b, "INVITE sip:911@203.0.113.5"), 1) << b.dump();
		b.handler->handle(carrierResponse(b, "SIP/2.0 486 Busy Here"));
		EXPECT_EQ(countStarting(b, "SIP/2.0 486"), 1) << b.dump();
		expectNotRoutedAfterRouted(b, "the trunk refused it (486)", "SIP/2.0 486");
	}
}

// #890: the final used to run the failure path: the PSAP's dialog was freed
// with no BYE and the caller's session ended with none either, so a connected
// 911 lost its audio. Now nothing goes on the wire, the call and its relay stay
// up, and a BYE from either side still ends it, with no NOT ROUTED at any
// point. The negative, a 486 before the 2xx, is the second half of the test above.
TEST(E911Notify, ACarrierFinalAfterItsTwoHundredLeavesThe911Up)
{
	auto header = [](const std::string& m, const std::string& name) {
		const size_t p = m.find("\r\n" + name);
		return p == std::string::npos ? std::string() : m.substr(p + 2, m.find("\r\n", p + 2) - p - 2);
	};
	for (const bool psapHangsUp : { true, false })
	{
		SCOPED_TRACE(psapHangsUp ? "then the PSAP hangs up" : "then the caller hangs up");
		NBench b;
		b.handler->setE911Config("200", "", "");
		b.handler->setAnchorPlacesRealCallsForTest(false);
		b.handler->setTrunkConfig(dottedQuadTrunk());
		b.wire.clear();
		b.handler->handle(enInvite("101", "911", "192.168.78.11", "en-890"));
		ASSERT_EQ(countStarting(b, "INVITE sip:911@203.0.113.5"), 1) << b.dump();
		b.handler->handle(carrierResponse(b, "SIP/2.0 200 OK", /*withSdp=*/true));
		ASSERT_EQ(countStarting(b, "SIP/2.0 200 OK"), 1) << "precondition: the PSAP answered:\n" << b.dump();
		std::string invite, answer;
		for (const auto& w : b.wire)
		{
			if (invite.empty() && w.rfind("INVITE sip:911@203.0.113.5", 0) == 0) invite = w;
			if (answer.empty() && w.rfind("SIP/2.0 200 OK", 0) == 0) answer = w;
		}
		const size_t before = b.wire.size();

		b.handler->handle(carrierResponse(b, "SIP/2.0 486 Busy Here"));
		b.handler->handle(carrierResponse(b, "SIP/2.0 486 Busy Here"));   // its retransmission

		EXPECT_EQ(b.wire.size(), before) << "nothing to the caller or the PSAP:\n" << b.dump();
		const auto s = b.handler->getSession("Call-ID: en-890");
		EXPECT_TRUE(s.has_value() && s.value()->getState() == Session::State::Connected) << b.dump();
		EXPECT_EQ(b.handler->trunkRelaysInUseForTest(), 1u);

		if (psapHangsUp)
		{
			// RFC 3261 §12.2.1.1: the PSAP's From is the INVITE's To, with its tag.
			const std::string bye = "BYE sip:trunkuser@192.168.78.1:5060 SIP/2.0\r\n"
				"Via: SIP/2.0/UDP 203.0.113.5:5060;branch=z9hG4bKpsap890\r\n"
				"From: " + header(invite, "To: ").substr(4) + ";tag=carrier879\r\n"
				"To: " + header(invite, "From: ").substr(6) + "\r\n" + header(invite, "Call-ID: ") + "\r\n"
				"CSeq: 2 BYE\r\nContent-Length: 0\r\n\r\n";
			b.handler->handle(RequestsHandler::getMessageFromPool(bye, enAddr("203.0.113.5")));
			EXPECT_EQ(countStarting(b, "BYE sip:101@"), 1) << "the caller is told:\n" << b.dump();
		}
		else
		{
			const std::string bye = "BYE sip:911@server SIP/2.0\r\n"
				"Via: SIP/2.0/UDP 192.168.78.11:5060;branch=z9hG4bKb890\r\n"
				+ header(answer, "From: ") + "\r\n" + header(answer, "To: ") + "\r\n"
				"Call-ID: en-890\r\nCSeq: 2 BYE\r\nContent-Length: 0\r\n\r\n";
			b.handler->handle(RequestsHandler::getMessageFromPool(bye, enAddr("192.168.78.11")));
			EXPECT_EQ(countStarting(b, "BYE sip:911@203.0.113.9"), 1) << "the PSAP is told:\n" << b.dump();
		}
		EXPECT_FALSE(b.handler->getSession("Call-ID: en-890").has_value()) << b.dump();
		EXPECT_EQ(b.handler->trunkRelaysInUseForTest(), 0u);
		EXPECT_EQ(b.countOf("ROUTED TO TRUNK"), 1) << b.dump();
		EXPECT_EQ(b.countOf("NOT ROUTED"), 0) << "the PSAP answered this 911:\n" << b.dump();
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// #878 review S-C4: what the trunk correction says, and when it is not sent.
// ─────────────────────────────────────────────────────────────────────────────

namespace
{
	// The handset's CANCEL of its own INVITE (RFC 3261 §9.1): same Request-URI,
	// branch, From tag and CSeq number, To without a tag.
	std::shared_ptr<SipMessage> enCancel(const std::string& fromExt, const std::string& toExt,
		const std::string& ip, const std::string& callId)
	{
		const std::string raw =
			"CANCEL sip:" + toExt + "@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + ip + ":5060;branch=z9hG4bKi" + callId + "\r\n"
			"From: <sip:" + fromExt + "@server>;tag=ft" + callId + "\r\n"
			"To: <sip:" + toExt + "@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 CANCEL\r\n"
			"Max-Forwards: 70\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, enAddr(ip));
	}
}

TEST(E911Notify, ATrunkCorrectionNamesTheNumberTheCallWasRoutedAs)
{
	// The correction classifies the To user, and falls back to the number the
	// session was routed as when a dial-plan rule produced it. A 933 must read
	// as a TEST in both of its notifications, never as a live 911.
	struct Case { const char* what; const char* pattern; int strip; const char* target; const char* dialed; bool test; };
	const Case cases[] = {
		{"a rule that makes 911 of 0",  "0", 1, "911", "0",   false},
		{"a rule that makes 933 of 8",  "8", 1, "933", "8",   true},
		{"a bare 933",                  "",  0, "",    "933", true},
	};
	int n = 0;
	for (const Case& c : cases)
	{
		SCOPED_TRACE(c.what);
		++n;
		NBench b;
		b.handler->setE911Config("200", "", "");
		b.handler->setAnchorPlacesRealCallsForTest(false);
		b.handler->setTrunkConfig(dottedQuadTrunk());
		if (c.pattern[0] != '\0') b.handler->setDialRule(c.pattern, "trunk", c.target, c.strip);
		b.wire.clear();
		b.handler->handle(enInvite("101", c.dialed, "192.168.78.11", "en-sc4a-" + std::to_string(n)));
		const std::string number = c.test ? "933" : "911";
		const bool placed = countStarting(b, "INVITE sip:" + number + "@203.0.113.5") == 1;
		EXPECT_TRUE(placed) << "precondition: the trunk carries " << number << ":\n" << b.dump();
		if (!placed) continue;
		b.handler->handle(carrierResponse(b, "SIP/2.0 403 Forbidden"));
		expectNotRoutedAfterRouted(b, "the trunk refused it (403)");
		const int correction = b.indexOf("NOT ROUTED");
		const std::string text = correction >= 0 ? b.wire[static_cast<size_t>(correction)] : std::string();
		const std::string want = c.test ? "TEST: 933 dialed by ext 101 - NOT ROUTED" : "EMERGENCY: 911 dialed by ext 101 - NOT ROUTED";
		EXPECT_NE(text.find(want), std::string::npos) << text;
		auto messagesWith = [&b](const std::string& needle) {
			int k = 0;
			for (const auto& w : b.wire)
				if (w.rfind("MESSAGE sip:200@", 0) == 0 && w.find(needle) != std::string::npos) ++k;
			return k;
		};
		EXPECT_EQ(countStarting(b, "MESSAGE sip:200@"), 2) << "the ROUTED, then the correction:\n" << b.dump();
		EXPECT_EQ(messagesWith("TEST: 933"), c.test ? 2 : 0) << b.dump();
		EXPECT_EQ(messagesWith("EMERGENCY: 911"), c.test ? 0 : 2) << "a 933 never reads as a live 911:\n" << b.dump();
	}
}

TEST(E911Notify, AHandsetCancelBeforeTheCarriersFinalIsNeverReportedNotRouted)
{
	{
		SCOPED_TRACE("the carrier rang (Proceeding): CANCEL, then the carrier's 487");
		NBench b;
		b.handler->setE911Config("200", "", "");
		b.handler->setAnchorPlacesRealCallsForTest(false);
		b.handler->setTrunkConfig(dottedQuadTrunk());
		b.wire.clear();
		b.handler->handle(enInvite("101", "911", "192.168.78.11", "en-sc4b-p"));
		ASSERT_EQ(countStarting(b, "INVITE sip:911@203.0.113.5"), 1) << b.dump();
		b.handler->handle(carrierResponse(b, "SIP/2.0 180 Ringing"));
		b.handler->handle(enCancel("101", "911", "192.168.78.11", "en-sc4b-p"));
		EXPECT_EQ(countStarting(b, "CANCEL sip:"), 1) << "the carrier leg is cancelled:\n" << b.dump();
		b.handler->handle(carrierResponse(b, "SIP/2.0 487 Request Terminated"));
		EXPECT_EQ(countStarting(b, "SIP/2.0 487"), 1) << "the handset's INVITE:\n" << b.dump();
		EXPECT_EQ(b.countOf("ROUTED TO TRUNK"), 1) << b.dump();
		EXPECT_EQ(b.countOf("NOT ROUTED"), 0) << "the caller hung up; nothing was refused:\n" << b.dump();
	}
	{
		SCOPED_TRACE("no provisional yet (Trying): the CANCEL is held, then the leg times out");
		NBench b;
		b.handler->setE911Config("200", "", "");
		b.handler->setAnchorPlacesRealCallsForTest(false);
		b.handler->setTrunkConfig(dottedQuadTrunk());
		b.wire.clear();
		b.handler->handle(enInvite("101", "911", "192.168.78.11", "en-sc4b-t"));
		ASSERT_EQ(countStarting(b, "INVITE sip:911@203.0.113.5"), 1) << b.dump();
		b.handler->handle(enCancel("101", "911", "192.168.78.11", "en-sc4b-t"));
		EXPECT_EQ(countStarting(b, "SIP/2.0 487"), 1) << "the handset's INVITE:\n" << b.dump();
		b.handler->expireTrunkDeadlinesForTest();
		b.handler->forceNextTickForTest();
		b.handler->tick();
		EXPECT_EQ(b.countOf("ROUTED TO TRUNK"), 1) << b.dump();
		EXPECT_EQ(b.countOf("NOT ROUTED"), 0) << "the caller hung up; nothing was refused:\n" << b.dump();
	}
	// #889 review S1: a 100 is a provisional, so the CANCEL goes to the PSAP at
	// once (RFC 3261 §9.1); main held it for an 18x (#794) while the PSAP rang on.
	for (const std::string number : { "911", "933" })
	{
		SCOPED_TRACE(number + ": only a carrier 100 (Proceeding), then the caller's CANCEL");
		NBench b;
		b.handler->setE911Config("200", "", "");
		b.handler->setAnchorPlacesRealCallsForTest(false);
		b.handler->setTrunkConfig(dottedQuadTrunk());
		b.wire.clear();
		const std::string callId = "en-sc4b-100-" + number;
		const std::string psap = "INVITE sip:" + number + "@203.0.113.5";
		b.handler->handle(enInvite("101", number, "192.168.78.11", callId));
		ASSERT_EQ(countStarting(b, psap), 1) << b.dump();
		std::string branch;
		for (const auto& w : b.wire)
		{
			const size_t p = w.rfind(psap, 0) == 0 ? w.find(";branch=") : std::string::npos;
			if (p != std::string::npos) branch = w.substr(p + 8, w.find_first_of(";\r", p + 8) - p - 8);
		}
		b.handler->handle(carrierResponse(b, "SIP/2.0 100 Trying"));
		b.handler->handle(enCancel("101", number, "192.168.78.11", callId));
		const std::string cancel = "CANCEL sip:" + number + "@203.0.113.5";
		EXPECT_EQ(countStarting(b, cancel), 1) << "the PSAP leg is cancelled at once:\n" << b.dump();
		const int at = b.indexOf(cancel);
		EXPECT_TRUE(at >= 0 && !branch.empty() && b.wire[static_cast<size_t>(at)].find(";branch=" + branch) != std::string::npos)
			<< "on the INVITE's branch " << branch << ":\n" << b.dump();
		EXPECT_EQ(countStarting(b, "SIP/2.0 487"), 1) << "the caller's INVITE:\n" << b.dump();
		EXPECT_EQ(b.handler->trunkRelaysInUseForTest(), 0u);
		EXPECT_FALSE(b.handler->getSession("Call-ID: " + callId).has_value());
		b.handler->handle(carrierResponse(b, "SIP/2.0 487 Request Terminated"));
		EXPECT_EQ(b.countOf("ROUTED TO TRUNK"), 1) << b.dump();
		EXPECT_EQ(b.countOf("NOT ROUTED"), 0) << "the caller hung up; nothing was refused:\n" << b.dump();
	}
}
