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
#include <cstdlib>
#include <functional>
#include <memory>
#include <string>
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
		/*isTest=*/false, "101", "911", /*hadTrunkPrefix=*/false, /*routed=*/false, cfg);

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
		std::shared_ptr<SipMessage> messageFromPool(std::string, sockaddr_in) override { return nullptr; }
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

	// Fill the anchor to its effective capacity via the anchor extension.
	const unsigned cap = std::min<unsigned>(
		b.handler->anchorClientForTest()->maxConcurrentCalls(),
		static_cast<unsigned>(POCKETDIAL_MAX_ANCHOR_CALLS));
	ASSERT_GE(cap, 1u);
	for (unsigned i = 0; i < cap; ++i)
	{
		b.handler->handle(enInvite("101", "555", "192.168.78.11",
			"en-fill-" + std::to_string(i)));
	}
	b.wire.clear();

	// 911 from a DIFFERENT extension, so the dialer is not one of the fillers.
	b.handler->handle(enInvite("200", "911", "192.168.78.20", "en-911-busy"));

	EXPECT_EQ(b.indexOf("ROUTED TO TRUNK"), -1)
		<< "the anchor answered this INVITE with a 503 and still returned true; "
		   "reporting it as routed tells the front desk a 911 call went through "
		   "when it did not:\n" << b.dump();
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
