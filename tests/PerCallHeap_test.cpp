// PerCallHeap_test.cpp -- the per-call heap leak that blocked the v1.5.0-rc.1
// soak: internal DRAM fell ~56 KB/h under 888 + re-REGISTER load and stayed
// flat when idle.
//
// A pooled SipMessage keeps the header-line buffers a shorter message did not
// need in _spareHeaderLines (#462), for the next longer message to reuse. A
// header INSERTED into a response (addCapabilityHeaders' Accept/Allow-Events
// when the request lacked them, or any setter for a header that is absent)
// adopted a fresh string instead, and the slot's next reset() parked the surplus
// line. So every reuse of a slot to build such a response grew it by one string
// per inserted header, for good. The 888 answer and every REGISTER 200 insert
// headers; the 777 echo answer only replaces lines its INVITE already carries,
// which is why 777 never leaked.
//
// The handler-level tests drive real dialogs and require the number of live
// operator-new blocks (tests/support/AllocCounter) to be back at its baseline
// after every call once warmed up. Live bytes are bounded rather than exact: a
// pooled line buffer can be handed a longer header and grow once. The requests
// carry the Allow and Supported headers a pjsua-style UA sends, so the answers
// still insert Accept and Allow-Events.

#include <gtest/gtest.h>

#include <chrono>
#include <cstdio>
#include <memory>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "CallDetailRecord.hpp"
#include "ConferenceRoom.hpp"
#include "PoolConfig.hpp"
#include "RequestsHandler.hpp"
#include "SipMessage.hpp"
#include "support/AllocCounter.hpp"

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#else
#include <arpa/inet.h>
#endif

namespace
{
	using SentList = std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>>;

	// Calls rotate over this many phones, each on its own IP: the per-source
	// rate limit (burst 40, 20 packets/s) would otherwise refuse a test that
	// places calls faster than a person can.
	constexpr int kPhones = 8;
	constexpr int kWarmup = 2 * kPhones;
	constexpr int kMeasured = 2 * kPhones;
	// Live bytes may end above the baseline by this much (one-off growth of a
	// line buffer). The leak cost ~48 B per inserted header per call on host,
	// plus the parked-line vector doubling now and then.
	constexpr std::size_t kByteSlack = 512;

	sockaddr_in addrFor(const std::string& ip)
	{
		sockaddr_in a{};
		a.sin_family = AF_INET;
		a.sin_addr.s_addr = inet_addr(ip.c_str());
		a.sin_port = htons(5060);
		return a;
	}

	std::string extOf(int k) { return std::to_string(100 + k); }
	std::string ipOf(int k) { return "192.168.64." + std::to_string(10 + k); }

	// Fixed width, and longer than the small-string buffer as a real UA's are,
	// so a string that keeps one Call-ID reuses its buffer for the next.
	std::string fixedId(const char* kind, int n)
	{
		char buf[48];
		std::snprintf(buf, sizeof buf, "%s-%05d-5c0a9e7d41b2f6a3", kind, n);
		return buf;
	}

	std::string headerValue(const std::string& raw, const std::string& name)
	{
		size_t pos = 0;
		while (pos < raw.size())
		{
			size_t eol = raw.find("\r\n", pos);
			if (eol == std::string::npos) eol = raw.size();
			if (eol == pos) break;
			if (raw.compare(pos, name.size() + 1, name + ":") == 0)
			{
				size_t v = pos + name.size() + 1;
				while (v < eol && raw[v] == ' ') ++v;
				return raw.substr(v, eol - v);
			}
			pos = eol + 2;
		}
		return {};
	}

	const char* const kUaAllow =
		"Allow: PRACK, INVITE, ACK, BYE, CANCEL, UPDATE, INFO, SUBSCRIBE, NOTIFY, REFER, MESSAGE, OPTIONS\r\n";

	std::shared_ptr<SipMessage> makeRegister(int k, int cseq, int expires)
	{
		const std::string ext = extOf(k), ip = ipOf(k);
		std::string raw =
			"REGISTER sip:server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + ip + ":5060;rport;branch=z9hG4bKr" + fixedId("reg", cseq) + "\r\n"
			"Max-Forwards: 70\r\n"
			"From: <sip:" + ext + "@server>;tag=rt" + ext + "\r\n"
			"To: <sip:" + ext + "@server>\r\n"
			"Call-ID: " + fixedId("reg", k) + "\r\n"
			"CSeq: " + std::to_string(cseq) + " REGISTER\r\n"
			"User-Agent: PJSUA v2.14 Linux\r\n"
			"Supported: outbound, path\r\n"
			"Contact: <sip:" + ext + "@" + ip + ":5060;ob>;expires=" + std::to_string(expires) + "\r\n"
			+ kUaAllow +
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addrFor(ip));
	}

	std::shared_ptr<SipMessage> makeInvite(int k, const std::string& to, const std::string& callId)
	{
		const std::string from = extOf(k), ip = ipOf(k);
		const std::string body =
			"v=0\r\n"
			"o=- 3900000000 3900000000 IN IP4 " + ip + "\r\n"
			"s=pjmedia\r\n"
			"c=IN IP4 " + ip + "\r\n"
			"t=0 0\r\n"
			"m=audio 4000 RTP/AVP 0 101\r\n"
			"a=rtpmap:0 PCMU/8000\r\n"
			"a=rtpmap:101 telephone-event/8000\r\n"
			"a=fmtp:101 0-16\r\n"
			"a=sendrecv\r\n";
		std::string raw =
			"INVITE sip:" + to + "@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + ip + ":5060;rport;branch=z9hG4bKi" + callId + "\r\n"
			"Max-Forwards: 70\r\n"
			"From: <sip:" + from + "@server>;tag=ft" + callId + "\r\n"
			"To: <sip:" + to + "@server>\r\n"
			"Contact: <sip:" + from + "@" + ip + ":5060;ob>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 4000 INVITE\r\n"
			+ kUaAllow +
			"Supported: replaces, 100rel, timer, norefersub\r\n"
			"User-Agent: PJSUA v2.14 Linux\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		return RequestsHandler::getMessageFromPool(raw, addrFor(ip));
	}

	std::shared_ptr<SipMessage> makeInDialog(const char* method, int k, const std::string& to,
		const std::string& toHdr, const std::string& callId, int cseq)
	{
		const std::string from = extOf(k), ip = ipOf(k);
		std::string raw =
			std::string(method) + " sip:" + to + "@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + ip + ":5060;rport;branch=z9hG4bK" + method + callId + "\r\n"
			"Max-Forwards: 70\r\n"
			"From: <sip:" + from + "@server>;tag=ft" + callId + "\r\n"
			"To: " + toHdr + "\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: " + std::to_string(cseq) + " " + method + "\r\n"
			"User-Agent: PJSUA v2.14 Linux\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addrFor(ip));
	}

	// Gives every slot of the process-wide message pool more and longer header
	// lines than any message below, so which slot a message lands in (that
	// depends on what else is in flight, e.g. the 5 s OPTIONS pings) never shows
	// up as a slot's first-use allocation inside a measurement.
	void warmMessagePool()
	{
		std::string raw = "OPTIONS sip:warm@server SIP/2.0\r\n";
		for (int i = 0; i < 24; ++i)
		{
			raw += "X-Warm-" + std::to_string(i) + ": " + std::string(160, 'w') + "\r\n";
		}
		raw += "Content-Length: 0\r\n\r\n";
		std::vector<std::shared_ptr<SipMessage>> held;
		for (int i = 0; i < POCKETDIAL_MSG_POOL; ++i)
		{
			if (auto m = RequestsHandler::getMessageFromPool(raw, addrFor("192.168.64.250")))
			{
				held.push_back(std::move(m));
			}
		}
	}

	struct Dialog
	{
		int k = 0;
		std::string to, callId, toHdr;
	};

	struct Rig
	{
		SentList sent;
		RequestsHandler handler;
		int regCseq = 1000;

		Rig() : handler("192.168.64.1", 5060,
			[this](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
				sent.emplace_back(addr, std::move(msg));
			})
		{
			warmMessagePool();
			for (int k = 0; k < kPhones; ++k) handler.handle(makeRegister(k, ++regCseq, 300));
			// The first registrations queue register beeps; decline them now so the
			// beep table starts every measurement empty.
			declineBeeps();
			// A full CDR ring, so the dashboard snapshot's call list (both of its
			// swapped copies) is at its bounded size before anything is measured.
			for (int i = 0; i < POCKETDIAL_CDR_RECORDS; ++i) handler.recordCallForTest(extOf(i % kPhones), "888");
			settle();
			settle();
		}

		// Fire the pending register beeps and decline each with 486, as a busy
		// phone does. Returns how many there were.
		int declineBeeps()
		{
			sent.clear();
			handler.fireRegisterBeepsForTest();
			int n = 0;
			for (const auto& [addr, msg] : SentList(sent))
			{
				const std::string raw = msg ? msg->toString() : std::string();
				if (raw.rfind("INVITE ", 0) != 0) continue;
				++n;
				const std::string busy =
					"SIP/2.0 486 Busy Here\r\n"
					"Via: " + headerValue(raw, "Via") + "\r\n"
					"From: " + headerValue(raw, "From") + "\r\n"
					"To: " + headerValue(raw, "To") + ";tag=busy486\r\n"
					"Call-ID: " + headerValue(raw, "Call-ID") + "\r\n"
					"CSeq: " + headerValue(raw, "CSeq") + "\r\n"
					"Content-Length: 0\r\n\r\n";
				handler.handle(RequestsHandler::getMessageFromPool(busy, addr));
			}
			return n;
		}

		// What wall time would do between calls: transactions past their timers,
		// one tick, the outbox released.
		void settle()
		{
			handler.sweepTransactionsForTest(std::chrono::steady_clock::now() + std::chrono::minutes(5));
			handler.forceNextTickForTest();
			handler.tick();
			sent.clear();
		}

		// INVITE -> 200 -> ACK.
		bool answer(Dialog& d, int k, const std::string& to, int call)
		{
			const std::string callId = fixedId("call", call);
			sent.clear();
			handler.handle(makeInvite(k, to, callId));
			for (const auto& [addr, msg] : sent)
			{
				(void)addr;
				const std::string raw = msg ? msg->toString() : std::string();
				if (raw.rfind("SIP/2.0 200 OK", 0) == 0 && headerValue(raw, "Call-ID") == callId)
				{
					d = Dialog{k, to, callId, headerValue(raw, "To")};
					handler.handle(makeInDialog("ACK", k, to, d.toHdr, callId, 4000));
					return true;
				}
			}
			return false;
		}

		// BYE. A conference leg that leaves keeps its MixBus port (Draining) until
		// the next mix tick, so a test placing calls faster than the 20 ms driver
		// would find the room full. Step that tick here instead, with the driver
		// stopped so there is still one tick path; the next 888 INVITE restarts it.
		void hangUp(const Dialog& d)
		{
			handler.handle(makeInDialog("BYE", d.k, d.to, d.toHdr, d.callId, 4001));
			if (d.to == "888")
			{
				ConferenceRoom* room = handler.conferenceForTest();
				room->stopDriver();
				room->tickOnce();
			}
		}
	};

	struct Live
	{
		std::size_t blocks;
		std::size_t bytes;
	};

	// Runs `cycle` kWarmup + kMeasured times, settling after each, and returns
	// the live totals after each measured cycle, preceded by the baseline.
	template <typename Cycle>
	std::vector<Live> measure(Rig& r, Cycle&& cycle)
	{
		std::vector<Live> s;
		s.reserve(kMeasured + 1);
		for (int i = 0; i < kWarmup; ++i)
		{
			cycle(i);
			r.settle();
		}
		s.push_back({heapLiveBlocks(), heapLiveBytes()});
		for (int i = kWarmup; i < kWarmup + kMeasured; ++i)
		{
			cycle(i);
			r.settle();
			s.push_back({heapLiveBlocks(), heapLiveBytes()});
		}
		return s;
	}

	// The cycles whose live block count differs from the baseline, as
	// " cycle: +blocks/+bytes;". Empty when every call gave back all it took.
	std::string blockDrift(const std::vector<Live>& s)
	{
		std::ostringstream out;
		for (size_t i = 1; i < s.size(); ++i)
		{
			if (s[i].blocks == s[0].blocks) continue;
			out << " " << i << ": " << static_cast<long long>(s[i].blocks - s[0].blocks) << " blocks/"
				<< static_cast<long long>(s[i].bytes - s[0].bytes) << " B;";
		}
		return out.str();
	}

	long long byteGrowth(const std::vector<Live>& s)
	{
		return static_cast<long long>(s.back().bytes) - static_cast<long long>(s.front().bytes);
	}
}

// The mechanism alone, on one pooled message: rebuilding it many times with
// headers the request lacked must not keep growing it.
TEST(PerCallHeap, APooledMessageRebuiltManyTimesKeepsItsBuffers)
{
	if (!heapLiveTracked()) GTEST_SKIP() << "this C library cannot report block sizes";

	const std::string request =
		"INVITE sip:888@server SIP/2.0\r\n"
		"Via: SIP/2.0/UDP 192.168.64.10:5060;branch=z9hG4bKpooled-message-pin\r\n"
		"From: <sip:100@server>;tag=pooled-message-from\r\n"
		"To: <sip:888@server>\r\n"
		"Call-ID: pooled-message-pin-0123456789abcdef\r\n"
		"CSeq: 1 INVITE\r\n"
		"Content-Length: 0\r\n\r\n";
	const sockaddr_in src = addrFor("192.168.64.10");
	auto msg = std::make_shared<SipMessage>(request, src);

	// One of each insert path: setHeaderOnce, addHeader, and a named setter for
	// a header the request does not have.
	auto rebuild = [&] {
		msg->reset(request, src);
		msg->setHeaderOnce("Accept", "application/sdp, application/dtmf-relay");
		msg->addHeader("Allow-Events", "dialog, message-summary");
		msg->setContact("Contact: <sip:888@192.168.64.1:5060;transport=udp>");
	};
	for (int i = 0; i < 4; ++i) rebuild();
	const std::size_t blocks0 = heapLiveBlocks();
	const std::size_t bytes0 = heapLiveBytes();
	for (int i = 0; i < 64; ++i) rebuild();
	const std::size_t blocks1 = heapLiveBlocks();
	const std::size_t bytes1 = heapLiveBytes();
	const std::string built = msg->toString();

	EXPECT_EQ(blocks1, blocks0) << "header buffers retained per rebuild";
	EXPECT_EQ(bytes1, bytes0);
	EXPECT_NE(built.find("\r\nAccept: application/sdp"), std::string::npos) << built;
	EXPECT_NE(built.find("\r\nAllow-Events: dialog"), std::string::npos) << built;
	EXPECT_NE(built.find("\r\nContact: <sip:888@"), std::string::npos) << built;
}

// 888, one caller at a time.
TEST(PerCallHeap, ConferenceCallsReturnTheHeapToBaseline)
{
	if (!heapLiveTracked()) GTEST_SKIP() << "this C library cannot report block sizes";
	Rig r;
	int failed = 0;

	const auto s = measure(r, [&](int i) {
		Dialog d;
		if (!r.answer(d, i % kPhones, "888", i)) { ++failed; return; }
		r.hangUp(d);
	});
	const int legsLeft = r.handler.getConferenceLegs();

	EXPECT_EQ(failed, 0) << "a conference call was not answered; the heap figures prove nothing";
	EXPECT_EQ(legsLeft, 0);
	EXPECT_EQ(blockDrift(s), "");
	EXPECT_LE(byteGrowth(s), static_cast<long long>(kByteSlack));
}

// 888, two callers joining the room together and leaving it.
TEST(PerCallHeap, TwoPartyConferenceJoinAndLeaveReturnTheHeapToBaseline)
{
	if (!heapLiveTracked()) GTEST_SKIP() << "this C library cannot report block sizes";
	Rig r;
	int failed = 0;

	const auto s = measure(r, [&](int i) {
		Dialog a, b;
		const int ka = (2 * i) % kPhones;
		if (!r.answer(a, ka, "888", 2 * i)) { ++failed; return; }
		if (!r.answer(b, ka + 1, "888", 2 * i + 1)) { ++failed; r.hangUp(a); return; }
		if (r.handler.getConferenceLegs() != 2) ++failed;
		r.hangUp(b);
		r.hangUp(a);
	});
	const int legsLeft = r.handler.getConferenceLegs();

	EXPECT_EQ(failed, 0) << "a two-party conference did not come up; the heap figures prove nothing";
	EXPECT_EQ(legsLeft, 0);
	EXPECT_EQ(blockDrift(s), "");
	EXPECT_LE(byteGrowth(s), static_cast<long long>(kByteSlack));
}

// The control: the 777 echo answer only replaces headers its INVITE already
// carries, so it was never part of the leak and stays flat either way.
TEST(PerCallHeap, EchoCallsReturnTheHeapToBaseline)
{
	if (!heapLiveTracked()) GTEST_SKIP() << "this C library cannot report block sizes";
	Rig r;
	int failed = 0;

	const auto s = measure(r, [&](int i) {
		Dialog d;
		if (!r.answer(d, i % kPhones, "777", i)) { ++failed; return; }
		r.hangUp(d);
	});

	EXPECT_EQ(failed, 0) << "an echo call was not answered; the heap figures prove nothing";
	EXPECT_EQ(blockDrift(s), "");
	EXPECT_LE(byteGrowth(s), static_cast<long long>(kByteSlack));
}

// A phone refreshing its registration, and one registering afresh whose
// register beep it declines with 486: the soak's UA does one or the other
// every cycle.
TEST(PerCallHeap, ReRegisterAndADeclinedRegisterBeepReturnTheHeapToBaseline)
{
	if (!heapLiveTracked()) GTEST_SKIP() << "this C library cannot report block sizes";
	Rig r;
	int beepsNotOne = 0;

	const auto refresh = measure(r, [&](int i) {
		r.handler.handle(makeRegister(i % kPhones, ++r.regCseq, 300));
	});
	const auto rebind = measure(r, [&](int i) {
		r.handler.handle(makeRegister(i % kPhones, ++r.regCseq, 0));
		r.handler.handle(makeRegister(i % kPhones, ++r.regCseq, 300));
		if (r.declineBeeps() != 1) ++beepsNotOne;
	});

	EXPECT_EQ(beepsNotOne, 0) << "every fresh registration should draw exactly one beep";
	EXPECT_EQ(blockDrift(refresh), "") << "re-REGISTER of a registered phone";
	EXPECT_LE(byteGrowth(refresh), static_cast<long long>(kByteSlack));
	EXPECT_EQ(blockDrift(rebind), "") << "de-register, register, beep declined 486";
	EXPECT_LE(byteGrowth(rebind), static_cast<long long>(kByteSlack));
}
