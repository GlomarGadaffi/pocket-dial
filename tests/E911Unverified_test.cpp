// E911Unverified_test.cpp -- #1127.
//
// A 911/933 whose INVITE source IP is not the address the named extension
// registered from is reported as "caller unverified" in the E911 notification and
// in the EMERGENCY log lines. It is a reporting field only: the call is routed,
// answered and notified exactly as before (#454: 911 is never gated), and a
// verified caller's text is byte-for-byte what it was.

#include <gtest/gtest.h>

#include <chrono>
#include <functional>
#include <memory>
#include <thread>
#include <string>
#include <utility>
#include <vector>

#include "AlertCapture.hpp"
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
	const char* const kRegIp   = "192.168.9.51";   // where 501 registered from
	const char* const kOtherIp = "192.168.9.99";   // a different host naming 501
	const char* const kDeskIp  = "192.168.9.20";

	sockaddr_in uvAddr(const std::string& ip)
	{
		sockaddr_in s{};
		s.sin_family = AF_INET;
		s.sin_addr.s_addr = inet_addr(ip.c_str());
		s.sin_port = htons(5060);
		return s;
	}

	std::shared_ptr<SipMessage> uvRegister(const std::string& ext, const std::string& ip)
	{
		const std::string id = "uv-reg-" + ext;
		const std::string raw =
			"REGISTER sip:server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + ip + ":5060;branch=z9hG4bKr" + id + "\r\n"
			"From: <sip:" + ext + "@server>;tag=rt" + id + "\r\n"
			"To: <sip:" + ext + "@server>\r\n"
			"Call-ID: " + id + "\r\n"
			"CSeq: 1 REGISTER\r\n"
			"Contact: <sip:" + ext + "@" + ip + ":5060>;expires=3600\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, uvAddr(ip));
	}

	// `srcPort` differs from the registered 5060 where a test wants to show that
	// only the IP is compared.
	std::shared_ptr<SipMessage> uvInvite(const std::string& fromExt, const std::string& dialed,
		const std::string& ip, const std::string& callId, unsigned srcPort = 5060)
	{
		const std::string body =
			"v=0\r\no=- 0 0 IN IP4 " + ip + "\r\ns=-\r\nc=IN IP4 " + ip + "\r\nt=0 0\r\n"
			"m=audio 10000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n";
		const std::string raw =
			"INVITE sip:" + dialed + "@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + ip + ":5060;branch=z9hG4bKi" + callId + "\r\n"
			"From: <sip:" + fromExt + "@server>;tag=ft" + callId + "\r\n"
			"To: <sip:" + dialed + "@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Max-Forwards: 70\r\n"
			"Contact: <sip:" + fromExt + "@" + ip + ":5060>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		sockaddr_in src = uvAddr(ip);
		src.sin_port = htons(static_cast<uint16_t>(srcPort));
		return RequestsHandler::getMessageFromPool(raw, src);
	}

	size_t countOf(const std::string& hay, const std::string& needle)
	{
		size_t n = 0;
		for (size_t p = hay.find(needle); p != std::string::npos; p = hay.find(needle, p + needle.size())) ++n;
		return n;
	}

	std::string firstLine(const std::string& s) { return s.substr(0, s.find("\r\n")); }

	struct Sent { std::string ip; std::string text; };

	struct UvBench
	{
		std::vector<Sent> sent;
		std::unique_ptr<RequestsHandler> handler;

		UvBench()
		{
			handler = std::make_unique<RequestsHandler>("192.168.9.1", 5060,
				[this](const sockaddr_in& to, std::shared_ptr<SipMessage> m) {
					char ip[INET_ADDRSTRLEN] = {};
					inet_ntop(AF_INET, &to.sin_addr, ip, sizeof ip);
					sent.push_back({ip, m->toString()});
				});
			handler->handle(uvRegister("501", kRegIp));
			handler->handle(uvRegister("200", kDeskIp));   // the front desk
			handler->setAnchorPlacesRealCallsForTest(true);   // loopback stands in for the anchor
			handler->setE911Config("200", "", "");
			sent.clear();
		}

		LoopbackAnchorClient* loopback()
		{
			return dynamic_cast<LoopbackAnchorClient*>(handler->anchorClientForTest());
		}

		// Notifications that reached the front desk: MESSAGE bodies.
		std::vector<std::string> notifications() const
		{
			std::vector<std::string> out;
			for (const Sent& s : sent)
			{
				if (s.ip == kDeskIp && s.text.rfind("MESSAGE ", 0) == 0) out.push_back(s.text);
			}
			return out;
		}

		// First line of every message the caller's address was sent, in order.
		std::vector<std::string> responsesTo(const std::string& ip) const
		{
			std::vector<std::string> out;
			for (const Sent& s : sent)
			{
				if (s.ip == ip && s.text.rfind("SIP/2.0 ", 0) == 0) out.push_back(firstLine(s.text));
			}
			return out;
		}
	};

	struct Outcome
	{
		std::vector<std::string> notes;
		std::vector<std::string> responses;
		std::vector<std::string> frames;   // pbx-911 syslog
		std::string log;
		std::string dest;
		bool callbackOpen = false;
		bool emergencySession = false;
		bool bridged = false;
		int  state = -1;
	};

	Outcome dial(UvBench& b, const std::string& dialed, const std::string& fromIp, const std::string& id,
		unsigned srcPort = 5060)
	{
		AlertCapture cap;
		testing::internal::CaptureStderr();
		testing::internal::CaptureStdout();
		b.handler->handle(uvInvite("501", dialed, fromIp, id, srcPort));
		b.handler->forceNextTickForTest();
		b.handler->tick();   // drains the log queue and flushes the pbx-911 record
		Outcome r;
		r.log = testing::internal::GetCapturedStdout() + testing::internal::GetCapturedStderr();
		r.frames = AlertCapture::frames();
		r.notes = b.notifications();
		r.responses = b.responsesTo(fromIp);
		r.dest = b.loopback() ? b.loopback()->lastMakeCallDestination() : std::string();
		r.callbackOpen = b.handler->emergencyCallbackOpenForTest("501");
		auto s = b.handler->getSession("Call-ID: " + id);
		if (s.has_value())
		{
			r.emergencySession = s.value()->isEmergency();
			r.state = static_cast<int>(s.value()->getState());
		}
		r.bridged = b.handler->anchorBridgeForCallIdForTest("Call-ID: " + id) != nullptr;
		return r;
	}

	const char* const kFlag = "CALLER UNVERIFIED";

	// Lines of `log` that carry `needle`.
	std::vector<std::string> linesWith(const std::string& log, const std::string& needle)
	{
		std::vector<std::string> out;
		size_t pos = 0;
		while (pos < log.size())
		{
			size_t e = log.find('\n', pos);
			if (e == std::string::npos) e = log.size();
			const std::string line = log.substr(pos, e - pos);
			if (line.find(needle) != std::string::npos) out.push_back(line);
			pos = e + 1;
		}
		return out;
	}

	// The notification body of a captured MESSAGE.
	std::string bodyOf(const std::string& msg)
	{
		const size_t p = msg.find("\r\n\r\n");
		return p == std::string::npos ? std::string() : msg.substr(p + 4);
	}
}

// The notification text today, for a call that went to the anchor, with no
// callback or location configured. Golden: a verified caller must keep it.
static const char* const kGolden911 =
	"EMERGENCY: 911 dialed by ext 501 - ROUTED TO TRUNK - callback not configured";

TEST(E911Unverified, MismatchedSourceIsFlaggedAndStillRouted)
{
	UvBench b;
	ASSERT_NE(b.loopback(), nullptr);
	const Outcome r = dial(b, "911", kOtherIp, "uv-mm-1");

	ASSERT_EQ(r.notes.size(), 1u) << "exactly one notification";
	const std::string body = bodyOf(r.notes[0]);
	EXPECT_NE(body.find(kFlag), std::string::npos) << body;
	EXPECT_NE(body.find("ext 501"), std::string::npos) << body;
	EXPECT_NE(body.find("192.168.9.99"), std::string::npos) << body;
	EXPECT_EQ(countOf(body, kFlag), 1u) << body;

	EXPECT_EQ(r.dest, "911") << "routed in the same pass";
	ASSERT_EQ(r.frames.size(), 1u);
	EXPECT_EQ(countOf(r.frames[0], kFlag), 1u) << r.frames[0];

	// The EMERGENCY line written before routing carries it exactly once.
	const auto lines = linesWith(r.log, "EMERGENCY: 911 dialed by 501");
	ASSERT_EQ(lines.size(), 1u) << r.log;
	EXPECT_EQ(countOf(lines[0], kFlag), 1u) << lines[0];

	// Responses to the mismatched host: exactly those a matching host gets.
	UvBench ref;
	const Outcome m = dial(ref, "911", kRegIp, "uv-mm-1");
	EXPECT_EQ(r.responses, m.responses);
	// Recorded from main before the change: one final 200 and nothing else.
	EXPECT_EQ(r.responses, std::vector<std::string>{"SIP/2.0 200 OK"});
}

TEST(E911Unverified, MatchingSourceIsNotFlaggedAndByteIdentical)
{
	UvBench b;
	ASSERT_NE(b.loopback(), nullptr);
	const Outcome r = dial(b, "911", kRegIp, "uv-ok-1");

	ASSERT_EQ(r.notes.size(), 1u);
	EXPECT_EQ(bodyOf(r.notes[0]), kGolden911);
	EXPECT_EQ(r.notes[0].find("UNVERIFIED"), std::string::npos);
	ASSERT_EQ(r.frames.size(), 1u);
	EXPECT_EQ(r.frames[0].find("UNVERIFIED"), std::string::npos) << r.frames[0];
	EXPECT_EQ(r.log.find("UNVERIFIED"), std::string::npos) << r.log;
	EXPECT_EQ(r.dest, "911");
}

TEST(E911Unverified, MatchingIpFromAnotherPortIsNotFlagged)
{
	// Phones change ports: only the IP is compared.
	UvBench b;
	const Outcome r = dial(b, "911", kRegIp, "uv-port-1", 49152);
	ASSERT_EQ(r.notes.size(), 1u);
	EXPECT_EQ(bodyOf(r.notes[0]), kGolden911);
	EXPECT_EQ(r.log.find("UNVERIFIED"), std::string::npos) << r.log;
}

TEST(E911Unverified, MismatchedSourceDoesNotDelayOrRefuse)
{
	UvBench a;
	UvBench b;
	const Outcome mm = dial(a, "911", kOtherIp, "uv-ctl-1");
	const Outcome ok = dial(b, "911", kRegIp, "uv-ctl-1");

	EXPECT_EQ(mm.responses, ok.responses) << "same final response, same provisional sequence";
	EXPECT_EQ(mm.dest, "911");
	EXPECT_EQ(ok.dest, "911");
	EXPECT_TRUE(mm.emergencySession);
	EXPECT_EQ(mm.emergencySession, ok.emergencySession);
	EXPECT_EQ(mm.state, ok.state);
	EXPECT_EQ(mm.bridged, ok.bridged);
	EXPECT_TRUE(mm.callbackOpen) << "501's PSAP callback window opens either way";
	EXPECT_EQ(mm.callbackOpen, ok.callbackOpen);
	for (const std::string& line : mm.responses) EXPECT_EQ(line.find(" 403 "), std::string::npos) << line;
}

TEST(E911Unverified, TestNumber933CarriesTheFlagToo)
{
	UvBench b;
	const Outcome r = dial(b, "933", kOtherIp, "uv-933-1");
	ASSERT_EQ(r.notes.size(), 1u);
	const std::string body = bodyOf(r.notes[0]);
	EXPECT_EQ(body.rfind("TEST: 933", 0), 0u) << body;
	EXPECT_NE(body.find(kFlag), std::string::npos) << body;
	EXPECT_EQ(r.dest, "933");
}

TEST(E911Unverified, AnUnverifiedRegisteredCallerIsNotFoldedIntoUnknownCallerCoalescing)
{
	// #1129 coalesces refusals from callers that are not registered. 501 IS
	// registered, so each unverified dial from the same host keeps its own
	// notification and none of them reads as an unknown-caller tally.
	UvBench b;
	size_t notes = 0;
	for (int i = 0; i < 3; ++i)
	{
		const Outcome r = dial(b, "911", kOtherIp, "uv-co-" + std::to_string(i));
		notes = r.notes.size();
	}
	EXPECT_EQ(notes, 3u) << "three dials, three notifications (cumulative on the bench)";
	for (const std::string& n : b.notifications())
	{
		EXPECT_NE(bodyOf(n).find(kFlag), std::string::npos) << n;
		EXPECT_EQ(n.find("more since"), std::string::npos) << n;
		EXPECT_EQ(n.find("not a registered extension"), std::string::npos) << n;
	}
	EXPECT_EQ(b.handler->getE911UnknownAlertSuppressed(), 0u);
}

TEST(E911Unverified, TheFlagSurvivesTheMessageCap)
{
	pbx::E911Config cfg;
	cfg.callback = std::string(400, '5');
	cfg.location = std::string(400, 'x');
	const std::string s = pbx::formatE911Notification(false, "501", "911", false, true, cfg, {}, false,
		"192.168.9.99:5060");
	EXPECT_LE(s.size(), 512u);
	EXPECT_NE(s.find("CALLER UNVERIFIED: claimed ext 501, source 192.168.9.99:5060]"), std::string::npos) << s;
}

TEST(E911Unverified, AVerifiedFormatIsUnchangedByTheNewArgument)
{
	pbx::E911Config cfg;
	cfg.callback = "2025550123";
	cfg.location = "Front office";
	const char* const golden =
		"EMERGENCY: 911 dialed by ext 501 - ROUTED TO TRUNK - callback 2025550123 - Front office";
	EXPECT_EQ(pbx::formatE911Notification(false, "501", "911", false, true, cfg), golden);
	EXPECT_EQ(pbx::formatE911Notification(false, "501", "911", false, true, cfg, {}, false, {}), golden);
}

// The later notification for the SAME call: the anchor accepted the INVITE, then makeCall()
// failed on its worker. routeEmergencyCall() had said ROUTED; the NOT ROUTED correction
// must agree with it about who is calling from where.
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

	// The SIP thread's next pass drains _asyncOutbox; an OPTIONS from an unrelated host stands in.
	void flushAsyncOutbox(UvBench& b)
	{
		b.handler->handle(RequestsHandler::getMessageFromPool(
			"OPTIONS sip:server SIP/2.0
"
			"Via: SIP/2.0/UDP 192.168.9.98:5060;branch=z9hG4bKflush1127
"
			"From: <sip:probe@server>;tag=probe1127
"
			"To: <sip:server@server>
"
			"Call-ID: flush-1127
"
			"CSeq: 1 OPTIONS
"
			"Max-Forwards: 70
"
			"Content-Length: 0

", uvAddr("192.168.9.98")));
	}

	// Dials 911 as 501 from `ip`, fails the worker's makeCall(), returns the NOT ROUTED bodies.
	std::vector<std::string> notRoutedAfterMakeCallFails(const std::string& ip, const std::string& callId)
	{
		UvBench b;
		b.handler->failTelCtlLaneForTest(RequestsHandler::kLaneSos);
		b.handler->forceAsyncAnchorForTest(true);
		b.handler->holdTelCtlForTest(true);
		b.handler->handle(uvInvite("501", "911", ip, callId));
		EXPECT_TRUE(waitUntil([&] { return b.handler->telCtlParkedForTest() == 1; }));
		b.loopback()->stop();
		b.handler->holdTelCtlForTest(false);
		EXPECT_TRUE(waitUntil([&] { flushAsyncOutbox(b); return !b.responsesTo(ip).empty()
			&& b.responsesTo(ip).back().find(" 503 ") != std::string::npos; }));
		std::vector<std::string> out;
		for (const std::string& n : b.notifications())
		{
			if (bodyOf(n).find("NOT ROUTED") != std::string::npos) out.push_back(bodyOf(n));
		}
		return out;
	}
}

TEST(E911Unverified, ANotRoutedCorrectionForAnUnverifiedCallCarriesTheFlagAndSource)
{
	const auto nr = notRoutedAfterMakeCallFails(kOtherIp, "uv-nr-1");
	ASSERT_EQ(nr.size(), 1u);
	EXPECT_EQ(nr[0], std::string("EMERGENCY: 911 dialed by ext 501 - NOT ROUTED (the 3CX anchor could not "
		"place the call) - callback not configured [CALLER UNVERIFIED: claimed ext 501, source 192.168.9.99:5060]"));
}

TEST(E911Unverified, ANotRoutedCorrectionForAVerifiedCallIsByteIdenticalToToday)
{
	const auto nr = notRoutedAfterMakeCallFails(kRegIp, "uv-nr-2");
	ASSERT_EQ(nr.size(), 1u);
	EXPECT_EQ(nr[0], std::string("EMERGENCY: 911 dialed by ext 501 - NOT ROUTED (the 3CX anchor could not "
		"place the call) - callback not configured"));
}
