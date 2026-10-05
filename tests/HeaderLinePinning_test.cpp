// HeaderLinePinning_test.cpp -- #838: what a pooled SipMessage keeps of a
// hostile datagram.
//
// A pooled message keeps the line buffers of the most header lines it has held
// (#462 parks the ones a shorter message does not need, for the next longer
// one). splitMessage() stored every line before checkHeaders() counted them,
// and only a request was counted, so one 2 KB datagram of a thousand short
// lines left a thousand line slots in its pool slot for good (~48 KB on the
// ESP32), refused or not. A long line at a different position in each of 64
// datagrams did the same with buffer bytes: every position kept its largest.
//
// Each slot is first warmed with a legitimate maximum message, 64 header lines
// in one datagram. After any hostile datagram and normal reuse, the live
// operator-new totals (tests/support/AllocCounter, #837) must be back where the
// warm-up left them.

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <memory>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "PoolConfig.hpp"
#include "RequestsHandler.hpp"
#include "SipMessage.hpp"
#include "SipMessageFactory.hpp"
#include "SipMessagePool.hpp"
#include "UdpServer.hpp"
#include "support/AllocCounter.hpp"

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#else
#include <arpa/inet.h>
#endif

namespace
{
	constexpr size_t kDatagram = static_cast<size_t>(UdpServer::BUFFER_SIZE);
	constexpr int kMaxLines = static_cast<int>(SipLimits::kMaxHeaderLines);

	constexpr const char* kServerIp  = "192.168.83.1";
	constexpr const char* kCallerIp  = "192.168.83.50";   // ext 500
	constexpr const char* kCalleeIp  = "192.168.83.60";   // ext 600
	constexpr const char* kPinIp     = "192.168.83.70";   // the unit tests' sender
	constexpr const char* kHandsetIp = "192.168.83.80";   // ext 1001, trunk calls
	constexpr const char* kSbcIp     = "203.0.113.5";     // RFC 5737 TEST-NET-3

	using SentList = std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>>;

	sockaddr_in addrFor(const std::string& ip)
	{
		sockaddr_in a{};
		a.sin_family = AF_INET;
		a.sin_addr.s_addr = inet_addr(ip.c_str());
		a.sin_port = htons(5060);
		return a;
	}

	// A datagram off the socket, parsed the way SipServer::onNewMessage() does.
	std::shared_ptr<SipMessage> fromWire(const std::string& raw, const sockaddr_in& src)
	{
		SipMessageFactory factory;
		auto m = factory.createMessage(raw, src);
		return m ? *m : nullptr;
	}

	std::shared_ptr<SipMessage> fromWire(const std::string& raw, const std::string& ip)
	{
		return fromWire(raw, addrFor(ip));
	}

	struct Live
	{
		size_t blocks;
		size_t bytes;
	};

	Live live() { return {heapLiveBlocks(), heapLiveBytes()}; }

	long long byteGrowth(const Live& from, const Live& to)
	{
		return static_cast<long long>(to.bytes) - static_cast<long long>(from.bytes);
	}

	long long blockGrowth(const Live& from, const Live& to)
	{
		return static_cast<long long>(to.blocks) - static_cast<long long>(from.blocks);
	}

	std::string padLine(const char* fmt, int i)
	{
		char buf[64];
		std::snprintf(buf, sizeof buf, fmt, i, i);
		return buf;
	}

	// A well-formed message with exactly `lines` header lines (at least 7).
	// Every line is at least 16 characters, past the small-string buffer, so
	// each is a heap block of its own, as most real header lines are; a slot
	// warmed with it has a heap buffer at every position.
	std::string withHeaderLines(const std::string& startLine, int lines, const std::string& id)
	{
		std::string r = startLine + "\r\n"
			"Via: SIP/2.0/UDP " + std::string(kPinIp) + ":5060;branch=z9hG4bK" + id + "\r\n"
			"From: <sip:500@server>;tag=f" + id + "\r\n"
			"To: <sip:600@server>\r\n"
			"Call-ID: " + id + "\r\n"
			"CSeq: 101 OPTIONS\r\n"
			"Max-Forwards: 70\r\n";
		for (int i = 0; i < lines - 7; ++i) r += padLine("X-Line-%02d: legitimate-%02d\r\n", i);
		r += "Content-Length: 0\r\n\r\n";
		return r;
	}

	std::string legitimateMaximum()
	{
		return withHeaderLines("OPTIONS sip:pin@server SIP/2.0", kMaxLines, "legit-max-838");
	}

	const std::string kNormal =
		"OPTIONS sip:pin@server SIP/2.0\r\n"
		"Via: SIP/2.0/UDP 192.168.83.70:5060;branch=z9hG4bKnormal838\r\n"
		"From: <sip:500@server>;tag=normal838\r\n"
		"To: <sip:server>\r\n"
		"Call-ID: normal-838\r\n"
		"CSeq: 7 OPTIONS\r\n"
		"Content-Length: 0\r\n\r\n";

	// The shape in #838: one datagram of bare-LF one-character lines, about a
	// thousand of them, after `startLine`.
	std::string bareLfLines(const std::string& startLine)
	{
		std::string r = startLine + "\n";
		while (r.size() + 2 <= kDatagram) r += "a\n";
		return r;
	}

	// The same with 16-character lines, one past the small-string buffer, so
	// every line kept past the warm-up is a new heap block.
	std::string longerLines(const std::string& startLine)
	{
		const std::string line = "x-filler: 012345\r\n";
		std::string r = startLine + "\r\n";
		while (r.size() + line.size() <= kDatagram) r += line;
		return r;
	}

	// One message resetFromWire() in place, which is all a pool slot is for a
	// datagram (SipMessagePool.cpp: getMessageFromWire), warmed with a legitimate maximum
	// message and then a normal one. Its own object, not a slot of the
	// process-global pool: on unfixed code an earlier test may already have
	// grown every slot, and a baseline taken after that proves nothing.
	std::unique_ptr<SipMessage> warmedMessage(const sockaddr_in& src)
	{
		auto msg = std::make_unique<SipMessage>(std::string(), src);
		for (int i = 0; i < 2; ++i)
		{
			msg->resetFromWire(legitimateMaximum(), src);
			msg->resetFromWire(kNormal, src);
		}
		return msg;
	}

	struct PinResult
	{
		Live before{}, afterHostile{}, afterReuse{};
	};

	// A warmed message takes `hostile`, then a normal message.
	PinResult pinOneMessage(const std::string& hostile)
	{
		const sockaddr_in src = addrFor(kPinIp);
		PinResult r;
		auto msg = warmedMessage(src);
		r.before = live();
		msg->resetFromWire(hostile, src);
		r.afterHostile = live();
		msg->resetFromWire(kNormal, src);
		r.afterReuse = live();
		return r;
	}

	void expectBaseline(const PinResult& r)
	{
		EXPECT_EQ(byteGrowth(r.before, r.afterHostile), 0) << "live bytes kept while the slot is idle";
		EXPECT_EQ(blockGrowth(r.before, r.afterHostile), 0) << "live blocks kept while the slot is idle";
		EXPECT_EQ(byteGrowth(r.before, r.afterReuse), 0) << "live bytes kept after normal reuse";
		EXPECT_EQ(blockGrowth(r.before, r.afterReuse), 0) << "live blocks kept after normal reuse";
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

	std::shared_ptr<SipMessage> makeRegister(const std::string& ext, const std::string& ip)
	{
		const std::string raw =
			"REGISTER sip:server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + ip + ":5060;branch=z9hG4bKpin" + ext + "\r\n"
			"From: <sip:" + ext + "@server>;tag=pin" + ext + "\r\n"
			"To: <sip:" + ext + "@server>\r\n"
			"Call-ID: pin-reg-" + ext + "\r\n"
			"CSeq: 1 REGISTER\r\n"
			"Contact: <sip:" + ext + "@" + ip + ":5060>;expires=3600\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addrFor(ip));
	}

	std::string offerFrom(const std::string& ip)
	{
		return
			"v=0\r\n"
			"o=- 1 1 IN IP4 " + ip + "\r\n"
			"s=-\r\n"
			"c=IN IP4 " + ip + "\r\n"
			"t=0 0\r\n"
			"m=audio 40000 RTP/AVP 0 101\r\n"
			"a=rtpmap:0 PCMU/8000\r\n"
			"a=rtpmap:101 telephone-event/8000\r\n"
			"a=fmtp:101 0-16\r\n"
			"a=sendrecv\r\n";
	}

	// An INVITE from `fromExt` at `ip` to `to` with `lines` header lines in all
	// (at least 9): seven dialog lines, pad lines, then Content-Type and
	// Content-Length. At 65 lines the cut at 64 takes Content-Length.
	std::string invite(const std::string& fromExt, const std::string& ip, const std::string& to,
		const std::string& callId, int lines)
	{
		std::string r =
			"INVITE sip:" + to + "@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + ip + ":5060;branch=z9hG4bK" + callId + "\r\n"
			"From: <sip:" + fromExt + "@server>;tag=f" + callId + "\r\n"
			"To: <sip:" + to + "@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Max-Forwards: 70\r\n"
			"Contact: <sip:" + fromExt + "@" + ip + ":5060>\r\n";
		for (int i = 0; i < lines - 9; ++i) r += padLine("X-Pad-%02d: %02d\r\n", i);
		const std::string offer = offerFrom(ip);
		r += "Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(offer.size()) + "\r\n\r\n" + offer;
		return r;
	}

	// The seven dialog lines of an INVITE to 600, then one-character lines to
	// the end of a datagram: no body, no Content-Length.
	std::string hostileInvite(const std::string& callId)
	{
		std::string r =
			"INVITE sip:600@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + std::string(kCallerIp) + ":5060;branch=z9hG4bK" + callId + "\r\n"
			"From: <sip:500@server>;tag=f" + callId + "\r\n"
			"To: <sip:600@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Max-Forwards: 70\r\n"
			"Contact: <sip:500@" + std::string(kCallerIp) + ":5060>\r\n";
		while (r.size() + 3 <= kDatagram) r += "a\r\n";
		return r;
	}

	// `status` from 600 to the INVITE the PBX forked to it, with `lines` header
	// lines in all: the fork's Via lines, From, To (tagged), Call-ID, CSeq,
	// Contact, Content-Length, pad lines, and last "X-Last: kept" -- so whether
	// the last line survived is visible in what the caller is sent.
	std::string calleeResponse(const std::string& fork, const std::string& status, int lines)
	{
		std::string vias;
		int viaCount = 0;
		size_t pos = 0;
		while (pos < fork.size())
		{
			size_t eol = fork.find("\r\n", pos);
			if (eol == std::string::npos || eol == pos) break;
			if (fork.compare(pos, 4, "Via:") == 0)
			{
				vias += fork.substr(pos, eol - pos) + "\r\n";
				++viaCount;
			}
			pos = eol + 2;
		}
		std::string r = status + "\r\n" + vias +
			"From: " + headerValue(fork, "From") + "\r\n"
			"To: " + headerValue(fork, "To") + ";tag=callee838\r\n"
			"Call-ID: " + headerValue(fork, "Call-ID") + "\r\n"
			"CSeq: " + headerValue(fork, "CSeq") + "\r\n"
			"Contact: <sip:600@" + std::string(kCalleeIp) + ":5060>\r\n"
			"Content-Length: 0\r\n";
		const int fixed = viaCount + 6;
		for (int i = 0; i < lines - fixed - 1; ++i) r += padLine("X-Pad-%02d: %02d\r\n", i);
		r += "X-Last: kept\r\n\r\n";
		return r;
	}

	// A response from 600 that matches nothing in flight, `lines` header lines,
	// with the given pad line shape after the five dialog lines.
	std::string strayResponse(const std::string& callId, int lines)
	{
		std::string r =
			"SIP/2.0 200 OK\r\n"
			"Via: SIP/2.0/UDP " + std::string(kServerIp) + ":5060;branch=z9hG4bK" + callId + "\r\n"
			"From: <sip:500@server>;tag=f" + callId + "\r\n"
			"To: <sip:600@server>;tag=t" + callId + "\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 INVITE\r\n";
		for (int i = 0; i < lines - 6; ++i) r += padLine("X-Line-%02d: legitimate-%02d\r\n", i);
		r += "Content-Length: 0\r\n\r\n";
		return r;
	}

	std::string hostileResponse(const std::string& callId)
	{
		std::string r =
			"SIP/2.0 200 OK\r\n"
			"Via: SIP/2.0/UDP " + std::string(kServerIp) + ":5060;branch=z9hG4bK" + callId + "\r\n"
			"From: <sip:500@server>;tag=f" + callId + "\r\n"
			"To: <sip:600@server>;tag=t" + callId + "\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 INVITE\r\n";
		while (r.size() + 3 <= kDatagram) r += "a\r\n";
		return r;
	}

	// On exit, leaves every pool slot with no header lines and (nearly) no
	// parked buffers. A slot that held a 64-line message keeps its buffers
	// parked for reuse (#462), and PerCallHeap_test's per-cycle baselines
	// assume the pool holds no more than its own warm-up: each REGISTER 200
	// erases a Contact line and takes a parked buffer for the new one, so a
	// fuller slot drains by one block a cycle, which a shuffled run showed as
	// drift. Erasing the lines frees their buffers. A member declared first,
	// so it runs after a handler has released the slots it held.
	struct LeanPoolOnExit
	{
		LeanPoolOnExit() = default;
		LeanPoolOnExit(const LeanPoolOnExit&) = delete;
		LeanPoolOnExit& operator=(const LeanPoolOnExit&) = delete;
		~LeanPoolOnExit()
		{
			// Twice the wire cap: a message the PBX built can hold more than 64.
			std::string raw = "OPTIONS sip:lean@server SIP/2.0\r\n";
			for (int i = 0; i < 2 * kMaxLines; ++i) raw += "X-Lean: " + std::to_string(i) + "\r\n";
			raw += "\r\n";
			std::vector<std::shared_ptr<SipMessage>> held;
			held.reserve(POCKETDIAL_MSG_POOL);
			for (int i = 0; i < POCKETDIAL_MSG_POOL; ++i)
			{
				if (auto m = RequestsHandler::getMessageFromPool(raw, addrFor(kPinIp))) held.push_back(std::move(m));
			}
			for (const auto& m : held) m->removeHeaders("X-Lean");
		}
	};

	// Every pool slot holds a legitimate maximum message at once, so whichever
	// slot a message lands in has already had 64 line buffers.
	void warmEveryPoolSlot()
	{
		const std::string raw = legitimateMaximum();
		std::vector<std::shared_ptr<SipMessage>> held;
		held.reserve(POCKETDIAL_MSG_POOL);
		for (int i = 0; i < POCKETDIAL_MSG_POOL; ++i)
		{
			if (auto m = RequestsHandler::getMessageFromPool(raw, addrFor(kPinIp))) held.push_back(std::move(m));
		}
	}

	// 500 and 600 registered, their register beeps declined, every pool slot
	// warmed.
	struct Rig
	{
		LeanPoolOnExit lean;
		SentList sent;
		RequestsHandler handler;

		Rig() : handler(kServerIp, 5060,
			[this](const sockaddr_in& a, std::shared_ptr<SipMessage> m) { sent.emplace_back(a, std::move(m)); })
		{
			sent.reserve(256);
			warmEveryPoolSlot();
			handler.handle(makeRegister("500", kCallerIp));
			handler.handle(makeRegister("600", kCalleeIp));
			declineBeeps();
			settle();
			settle();
		}

		void declineBeeps()
		{
			sent.clear();
			handler.fireRegisterBeepsForTest();
			for (const auto& [addr, msg] : SentList(sent))
			{
				const std::string raw = msg ? msg->toString() : std::string();
				if (raw.rfind("INVITE ", 0) != 0) continue;
				const std::string busy =
					"SIP/2.0 486 Busy Here\r\n"
					"Via: " + headerValue(raw, "Via") + "\r\n"
					"From: " + headerValue(raw, "From") + "\r\n"
					"To: " + headerValue(raw, "To") + ";tag=busy838\r\n"
					"Call-ID: " + headerValue(raw, "Call-ID") + "\r\n"
					"CSeq: " + headerValue(raw, "CSeq") + "\r\n"
					"Content-Length: 0\r\n\r\n";
				handler.handle(fromWire(busy, addr));
			}
		}

		// Transactions past their timers, one tick (which drains the log queue),
		// the outbox released.
		void settle()
		{
			handler.sweepTransactionsForTest(std::chrono::steady_clock::now() + std::chrono::minutes(5));
			handler.forceNextTickForTest();
			handler.tick();
			sent.clear();
		}

		void send(const std::string& raw, const char* ip)
		{
			handler.handle(fromWire(raw, ip));
		}

		// Text of the first message sent to `ip` whose first line has `needle`.
		std::string first(const std::string& needle, const char* ip) const
		{
			const uint32_t want = inet_addr(ip);
			for (const auto& [addr, msg] : sent)
			{
				if (!msg || addr.sin_addr.s_addr != want) continue;
				const std::string raw = msg->toString();
				if (raw.substr(0, raw.find("\r\n")).find(needle) != std::string::npos) return raw;
			}
			return {};
		}

		size_t count(const std::string& needle, const char* ip) const
		{
			const uint32_t want = inet_addr(ip);
			size_t n = 0;
			for (const auto& [addr, msg] : sent)
			{
				if (!msg || addr.sin_addr.s_addr != want) continue;
				const std::string raw = msg->toString();
				if (raw.substr(0, raw.find("\r\n")).find(needle) != std::string::npos) ++n;
			}
			return n;
		}

		std::string dump() const
		{
			std::string out;
			for (const auto& [addr, msg] : sent)
			{
				(void)addr;
				if (!msg) continue;
				const std::string raw = msg->toString();
				out += raw.substr(0, raw.find("\r\n")) + "\n";
			}
			return out;
		}
	};

	// A handset (1001) and a trunk, as TrunkWiring_test.cpp sets them up.
	struct TrunkRig
	{
		LeanPoolOnExit lean;
		SentList sent;
		RequestsHandler handler;

		TrunkRig() : handler(kServerIp, 5060,
			[this](const sockaddr_in& a, std::shared_ptr<SipMessage> m) { sent.emplace_back(a, std::move(m)); })
		{
			SipTrunk::Config c;
			std::snprintf(c.host, sizeof(c.host), "%s", kSbcIp);
			c.port = 5060;
			std::snprintf(c.fromUser, sizeof(c.fromUser), "%s", "15551230000");
			c.enabled = true;
			handler.setTrunkConfig(c);
			handler.setDialRule("9XXXXXXXXXX", "trunk", "1", 1);
			handler.handle(makeRegister("1001", kHandsetIp));
			sent.clear();
		}

		std::string first(const std::string& needle, const char* ip) const
		{
			const uint32_t want = inet_addr(ip);
			for (const auto& [addr, msg] : sent)
			{
				if (!msg || addr.sin_addr.s_addr != want) continue;
				const std::string raw = msg->toString();
				if (raw.substr(0, raw.find("\r\n")).find(needle) != std::string::npos) return raw;
			}
			return {};
		}

		std::string dump() const
		{
			std::string out;
			for (const auto& [addr, msg] : sent)
			{
				(void)addr;
				if (!msg) continue;
				const std::string raw = msg->toString();
				out += raw.substr(0, raw.find("\r\n")) + "\n";
			}
			return out;
		}
	};

	// The carrier's answer to the INVITE the PBX sent it, `lines` header lines
	// in all: pad lines after Contact, then Content-Type and Content-Length, so
	// past 64 lines the cut takes those two.
	std::string carrierAnswer(const std::string& carrierInvite, int lines)
	{
		const std::string sdp =
			"v=0\r\no=- 0 0 IN IP4 203.0.113.9\r\ns=-\r\nc=IN IP4 203.0.113.9\r\n"
			"t=0 0\r\nm=audio 41000 RTP/AVP 0 101\r\na=rtpmap:0 PCMU/8000\r\n"
			"a=rtpmap:101 telephone-event/8000\r\n";
		std::string r = "SIP/2.0 200 OK\r\n"
			"Via: " + headerValue(carrierInvite, "Via") + "\r\n"
			"From: " + headerValue(carrierInvite, "From") + "\r\n"
			"To: " + headerValue(carrierInvite, "To") + ";tag=carrier-tag\r\n"
			"Call-ID: " + headerValue(carrierInvite, "Call-ID") + "\r\n"
			"CSeq: " + headerValue(carrierInvite, "CSeq") + "\r\n"
			"Contact: <sip:psap@203.0.113.9:5060>\r\n";
		for (int i = 0; i < lines - 8; ++i) r += padLine("X-Pad-%02d: %02d\r\n", i);
		r += "Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(sdp.size()) + "\r\n\r\n" + sdp;
		return r;
	}

	// The carrier's answer with four Record-Route lines across the cut: header
	// lines 62 to 65, the last of which is the route set's first hop
	// (RFC 3261 §12.1.2 reverses them).
	std::string carrierAnswerWithRecordRoute(const std::string& carrierInvite)
	{
		const std::string sdp =
			"v=0\r\no=- 0 0 IN IP4 203.0.113.9\r\ns=-\r\nc=IN IP4 203.0.113.9\r\n"
			"t=0 0\r\nm=audio 41000 RTP/AVP 0 101\r\na=rtpmap:0 PCMU/8000\r\n"
			"a=rtpmap:101 telephone-event/8000\r\n";
		std::string r = "SIP/2.0 200 OK\r\n"
			"Via: " + headerValue(carrierInvite, "Via") + "\r\n"
			"From: " + headerValue(carrierInvite, "From") + "\r\n"
			"To: " + headerValue(carrierInvite, "To") + ";tag=carrier-rr\r\n"
			"Call-ID: " + headerValue(carrierInvite, "Call-ID") + "\r\n"
			"CSeq: " + headerValue(carrierInvite, "CSeq") + "\r\n"
			"Contact: <sip:far@203.0.113.9:5060>\r\n";
		for (int i = 0; i < 55; ++i) r += padLine("X-P: %02d\r\n", i);
		for (int hop = 62; hop <= 65; ++hop) r += "Record-Route: <sip:10.9.9." + std::to_string(hop) + ";lr>\r\n";
		r += "Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(sdp.size()) + "\r\n\r\n" + sdp;
		return r;
	}

	// An INVITE from 500 to `to` carrying the session-timer headers a
	// pjsua-style UA sends, `lines` header lines in all (at least 12). The short
	// pad lines go before Content-Type and Content-Length, so on the PBX's own
	// answer the lines it adds land past line 64.
	std::string timerInvite(const std::string& to, const std::string& callId, int lines)
	{
		std::string r =
			"INVITE sip:" + to + "@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + std::string(kCallerIp) + ":5060;branch=z9hG4bK" + callId + "\r\n"
			"From: <sip:500@server>;tag=f" + callId + "\r\n"
			"To: <sip:" + to + "@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Max-Forwards: 70\r\n"
			"Contact: <sip:500@" + std::string(kCallerIp) + ":5060>\r\n"
			"Supported: replaces, timer\r\n"
			"Session-Expires: 1800;refresher=uac\r\n"
			"Require: timer\r\n";
		for (int i = 0; i < lines - 12; ++i) r += padLine("X-P: %02d\r\n", i);
		const std::string offer = offerFrom(kCallerIp);
		r += "Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(offer.size()) + "\r\n\r\n" + offer;
		return r;
	}

	// The header names of a message, sorted, without the X-P pad lines.
	std::vector<std::string> headerNames(const std::string& raw)
	{
		std::vector<std::string> names;
		size_t pos = raw.find("\r\n");
		while (pos != std::string::npos)
		{
			pos += 2;
			const size_t eol = raw.find("\r\n", pos);
			if (eol == std::string::npos || eol == pos) break;
			const std::string name = raw.substr(pos, raw.find(':', pos) - pos);
			if (name != "X-P") names.push_back(name);
			pos = eol;
		}
		std::sort(names.begin(), names.end());
		return names;
	}

	std::string bodyOf(const std::string& raw)
	{
		const size_t sep = raw.find("\r\n\r\n");
		return sep == std::string::npos ? std::string() : raw.substr(sep + 4);
	}
}

// ── The done-when: a 2 KB many-line request and response ────────────────────

TEST(HeaderLinePinning, AManyLineRequestDatagramLeavesAPooledMessageAtBaseline)
{
	if (!heapLiveTracked()) GTEST_SKIP() << "this C library cannot report block sizes";
	const std::string hostile = bareLfLines("OPTIONS sip:pin@server SIP/2.0");
	ASSERT_LE(hostile.size(), kDatagram);
	ASSERT_GT(hostile.size(), kDatagram - 4) << "precondition: one full datagram, about a thousand lines";
	expectBaseline(pinOneMessage(hostile));
}

TEST(HeaderLinePinning, AManyLineResponseDatagramLeavesAPooledMessageAtBaseline)
{
	if (!heapLiveTracked()) GTEST_SKIP() << "this C library cannot report block sizes";
	const std::string hostile = bareLfLines("SIP/2.0 200 OK");
	ASSERT_LE(hostile.size(), kDatagram);
	expectBaseline(pinOneMessage(hostile));
}

// Lines past the small-string buffer: each one kept is a heap block.
TEST(HeaderLinePinning, ManyLongerLinesDoNotKeepABlockEach)
{
	if (!heapLiveTracked()) GTEST_SKIP() << "this C library cannot report block sizes";
	for (const char* start : {"OPTIONS sip:pin@server SIP/2.0", "SIP/2.0 180 Ringing"})
	{
		SCOPED_TRACE(start);
		const std::string hostile = longerLines(start);
		ASSERT_LE(hostile.size(), kDatagram);
		expectBaseline(pinOneMessage(hostile));
	}
}

TEST(HeaderLinePinning, ManyLineDatagramsAcrossSeveralPoolSlotsDoNotGrowTheHeap)
{
	if (!heapLiveTracked()) GTEST_SKIP() << "this C library cannot report block sizes";
	sipmsgpool::ensureInitialized();
	const LeanPoolOnExit lean;
	constexpr int kSlots = 6;
	static_assert(kSlots <= POCKETDIAL_MSG_POOL, "the pool must have the slots this test holds");
	std::vector<std::shared_ptr<SipMessage>> held;
	held.reserve(kSlots);
	// Holds kSlots messages at once, so each lands in its own slot.
	auto drawAll = [&](const std::string& raw) {
		for (int i = 0; i < kSlots; ++i) held.push_back(fromWire(raw, kPinIp));
		size_t got = 0;
		for (const auto& m : held) if (m) ++got;
		held.clear();
		return got;
	};

	for (int round = 0; round < 2; ++round)
	{
		ASSERT_EQ(drawAll(legitimateMaximum()), static_cast<size_t>(kSlots));
		ASSERT_EQ(drawAll(kNormal), static_cast<size_t>(kSlots));
	}
	const std::vector<std::string> shapes = {bareLfLines("OPTIONS sip:pin@server SIP/2.0"),
		bareLfLines("SIP/2.0 200 OK"), longerLines("OPTIONS sip:pin@server SIP/2.0"),
		longerLines("SIP/2.0 200 OK")};
	const Live before = live();
	for (const std::string& hostile : shapes)
	{
		ASSERT_EQ(drawAll(hostile), static_cast<size_t>(kSlots));
		ASSERT_EQ(drawAll(kNormal), static_cast<size_t>(kSlots));
	}
	const Live after = live();

	EXPECT_EQ(byteGrowth(before, after), 0) << kSlots << " slots, four hostile shapes each";
	EXPECT_EQ(blockGrowth(before, after), 0);
}

// The count cap alone does not bound buffer BYTES: lines are reused in place by
// position, so a long line at position k in the k-th datagram leaves every
// position holding a large buffer. A pooled slot may keep no more than four
// datagrams' worth: one message's lines in use and one parked, each up to
// twice its size after string growth.
TEST(HeaderLinePinning, ALongLineAtEachPositionDoesNotKeepALargeBufferPerPosition)
{
	if (!heapLiveTracked()) GTEST_SKIP() << "this C library cannot report block sizes";
	const sockaddr_in src = addrFor(kPinIp);
	std::vector<std::string> attack;
	for (int k = 0; k < kMaxLines; ++k)
	{
		std::string raw = "OPTIONS sip:pin@server SIP/2.0\r\n";
		for (int i = 0; i < k; ++i) raw += "a: b\r\n";
		raw += "X-Long: ";
		raw += std::string(kDatagram - raw.size() - 2, 'L');
		raw += "\r\n";
		attack.push_back(std::move(raw));
	}
	const std::string allPositions = legitimateMaximum();
	auto msg = warmedMessage(src);
	const Live before = live();

	for (const std::string& raw : attack) msg->resetFromWire(raw, src);
	// Every position in use at once, then normal reuse.
	msg->resetFromWire(allPositions, src);
	msg->resetFromWire(kNormal, src);
	const Live after = live();

	// Allocator rounding on up to ~130 blocks is the slack.
	EXPECT_LE(byteGrowth(before, after), static_cast<long long>(4 * kDatagram + 2048))
		<< "a pooled slot kept a long line's buffer at every position";
}

// ── What a legitimate message at the edge still is ──────────────────────────

TEST(HeaderLinePinning, ASixtyFourLineMessageIsKeptWholeAndPasses)
{
	for (const char* start : {"OPTIONS sip:pin@server SIP/2.0", "SIP/2.0 200 OK"})
	{
		SCOPED_TRACE(start);
		const std::string raw = withHeaderLines(start, kMaxLines, "edge-64");
		ASSERT_LE(raw.size(), kDatagram);
		SipMessage m(raw, addrFor(kPinIp));
		EXPECT_EQ(m.toString(), raw) << "a legitimate 64-line message must be carried byte for byte";
		std::string_view unsupported;
		EXPECT_EQ(m.checkHeaders(unsupported), SipMessage::HeaderVerdict::Ok);
	}
}

TEST(HeaderLinePinning, ASixtyFiveLineRequestIsStillTooManyHeadersAfterACopy)
{
	sipmsgpool::ensureInitialized();
	const LeanPoolOnExit lean;
	std::string_view unsupported;

	auto over = fromWire(withHeaderLines("OPTIONS sip:pin@server SIP/2.0", kMaxLines + 1, "edge-65"), kPinIp);
	ASSERT_TRUE(over);
	EXPECT_EQ(over->checkHeaders(unsupported), SipMessage::HeaderVerdict::TooManyHeaders);

	// The pool's copy (operator=) of it is just as over the limit...
	auto copy = RequestsHandler::getMessageFromPool(*over);
	ASSERT_TRUE(copy);
	EXPECT_EQ(copy->checkHeaders(unsupported), SipMessage::HeaderVerdict::TooManyHeaders);

	// ...and a slot that held it, reused for a 64-line message, is not.
	const SipMessage* slot = over.get();
	over.reset();
	auto reused = fromWire(withHeaderLines("OPTIONS sip:pin@server SIP/2.0", kMaxLines, "edge-64r"), kPinIp);
	ASSERT_EQ(reused.get(), slot) << "precondition: the same slot";
	EXPECT_EQ(reused->checkHeaders(unsupported), SipMessage::HeaderVerdict::Ok);
	copy.reset();
	auto copyOfLegit = RequestsHandler::getMessageFromPool(*reused);
	ASSERT_TRUE(copyOfLegit);
	EXPECT_EQ(copyOfLegit->checkHeaders(unsupported), SipMessage::HeaderVerdict::Ok)
		<< "a copy over a slot that held a 65-line message must not inherit its verdict";
}

// ── Through handle(): the refusal, and the heap afterwards ──────────────────

TEST(HeaderLinePinning, AtTheEdgeAnInviteIsForwardedAndOneLineMoreIsRefused400)
{
	{
		Rig r;
		r.send(invite("500", kCallerIp, "600", "pin-edge-64", kMaxLines), kCallerIp);
		EXPECT_EQ(r.count("INVITE sip:600@", kCalleeIp), 1u) << "64 header lines:\n" << r.dump();
		EXPECT_EQ(r.count("SIP/2.0 400", kCallerIp), 0u) << r.dump();
	}
	{
		Rig r;
		r.send(invite("500", kCallerIp, "600", "pin-edge-65", kMaxLines + 1), kCallerIp);
		const std::string reply = r.first("SIP/2.0 400", kCallerIp);
		EXPECT_NE(reply.find("too many header lines"), std::string::npos) << "65 header lines:\n" << r.dump();
		EXPECT_EQ(r.count("INVITE", kCalleeIp), 0u) << r.dump();
	}
}

TEST(HeaderLinePinning, AManyLineRequestIsRefused400AndTheHeapReturnsToBaseline)
{
	if (!heapLiveTracked()) GTEST_SKIP() << "this C library cannot report block sizes";
	Rig r;
	// One-time growth on the refusal path (the 400's slot, its Warning line, the
	// log queue) happens here, on legitimate-shaped refusals.
	for (int i = 0; i < 2; ++i)
	{
		r.send(invite("500", kCallerIp, "600", "pin-warm-" + std::to_string(i), kMaxLines + 1), kCallerIp);
		ASSERT_EQ(r.count("SIP/2.0 400", kCallerIp), 1u) << r.dump();
		r.settle();
	}
	const std::string hostile = hostileInvite("pin-hostile-0");
	ASSERT_LE(hostile.size(), kDatagram);
	const Live before = live();

	r.send(hostile, kCallerIp);
	{
		const std::string reply = r.first("SIP/2.0 400", kCallerIp);
		EXPECT_NE(reply.find("too many header lines"), std::string::npos) << r.dump();
		EXPECT_EQ(r.count("INVITE", kCalleeIp), 0u) << "refused bytes must never reach the callee:\n" << r.dump();
	}
	r.settle();
	const Live after = live();

	EXPECT_EQ(blockGrowth(before, after), 0) << "the request's slot or its 400's slot kept blocks";
	EXPECT_LE(byteGrowth(before, after), 512) << "the request's slot or its 400's slot kept bytes";
}

TEST(HeaderLinePinning, AManyLineResponseLeavesTheHeapAtBaseline)
{
	if (!heapLiveTracked()) GTEST_SKIP() << "this C library cannot report block sizes";
	Rig r;
	for (int i = 0; i < 2; ++i)
	{
		r.send(strayResponse("pin-stray-warm-" + std::to_string(i), kMaxLines + 1), kCalleeIp);
		r.settle();
	}
	const std::string hostile = hostileResponse("pin-stray-hostile");
	ASSERT_LE(hostile.size(), kDatagram);
	const Live before = live();

	r.send(hostile, kCalleeIp);
	r.settle();
	const Live after = live();

	EXPECT_EQ(blockGrowth(before, after), 0) << "the response's slot kept blocks";
	EXPECT_LE(byteGrowth(before, after), 512) << "the response's slot kept bytes";
}

// A response cannot be answered, and refusing one would drop it -- which the
// header gate's 911 yield cannot prevent for a carrier's response on a 911
// trunk leg (that leg has its own Call-ID). So a response past the cap is acted
// on with the 64 header lines kept, like any response the gate passes.
TEST(HeaderLinePinning, AResponsePastTheCapIsActedOnWithItsFirstSixtyFourLines)
{
	Rig r;
	r.send(invite("500", kCallerIp, "600", "pin-ring", 12), kCallerIp);
	const std::string fork = r.first("INVITE sip:600@", kCalleeIp);
	ASSERT_FALSE(fork.empty()) << "precondition: the call rang 600:\n" << r.dump();

	r.sent.clear();
	r.send(calleeResponse(fork, "SIP/2.0 180 Ringing", kMaxLines), kCalleeIp);
	const std::string ring64 = r.first("SIP/2.0 180", kCallerIp);
	ASSERT_FALSE(ring64.empty()) << "a 64-line 180 is relayed:\n" << r.dump();
	EXPECT_NE(ring64.find("\r\nX-Last: kept\r\n"), std::string::npos)
		<< "positive control: the relay carries the callee's own lines\n" << ring64;

	r.sent.clear();
	r.send(calleeResponse(fork, "SIP/2.0 180 Ringing", kMaxLines + 1), kCalleeIp);
	const std::string ring65 = r.first("SIP/2.0 180", kCallerIp);
	ASSERT_FALSE(ring65.empty()) << "a 65-line 180 is not refused:\n" << r.dump();
	EXPECT_EQ(ring65.find("X-Last:"), std::string::npos)
		<< "the 65th header line is past the cap and is not kept:\n" << ring65;
}

// ── Emergency: the cap never costs a 911 ────────────────────────────────────

TEST(HeaderLinePinning, AnEmergencyInvitePastTheCapIsStillRoutedToTheCarrier)
{
	TrunkRig b;
	b.handler.handle(fromWire(invite("1001", kHandsetIp, "911", "pin-911-invite", kMaxLines + 6), kHandsetIp));
	EXPECT_FALSE(b.first("INVITE sip:911@", kSbcIp).empty())
		<< "a header-line count must never cost a 911 call:\n" << b.dump();
	EXPECT_TRUE(b.first("SIP/2.0 4", kHandsetIp).empty()) << b.dump();
}

TEST(HeaderLinePinning, ACarrierAnswerPastTheCapStillConnectsAnEmergencyCall)
{
	TrunkRig b;
	b.handler.handle(fromWire(invite("1001", kHandsetIp, "911", "pin-911-answer", 12), kHandsetIp));
	const std::string carrierInvite = b.first("INVITE sip:911@", kSbcIp);
	ASSERT_FALSE(carrierInvite.empty()) << "precondition: 911 went to the trunk:\n" << b.dump();
	b.sent.clear();

	b.handler.handle(fromWire(carrierAnswer(carrierInvite, kMaxLines + 6), kSbcIp));

	EXPECT_FALSE(b.first("ACK", kSbcIp).empty()) << "the carrier's 2xx must be ACKed:\n" << b.dump();
	EXPECT_FALSE(b.first("SIP/2.0 200 OK", kHandsetIp).empty())
		<< "the 911 caller must be connected:\n" << b.dump();
	EXPECT_EQ(b.handler.trunkRelaysInUseForTest(), 1u) << "the 911's media relay is up";
}

// ── #838 review: the PBX's own re-parses keep every line ────────────────────
//
// The cut is for datagrams off the socket. The PBX also re-parses messages it
// built itself: an answer serialised with its own headers added and then
// reset() (buildOkWithSdp, the 440 and 555 re-INVITE answers), and every stored
// retransmission (TransactionLayer::resend). A legal 64-line INVITE makes such
// an answer longer than 64 lines, and none of it may be lost.

TEST(HeaderLinePinning, TheAnswerToASixtyFourLineInviteKeepsEveryHeaderTheShortOneGets)
{
	for (const char* to : {"777", "888", "555"})
	{
		SCOPED_TRACE(to);
		std::string shortAnswer, longAnswer;
		{
			Rig r;
			r.send(timerInvite(to, std::string("pin-short-") + to, 12), kCallerIp);
			shortAnswer = r.first("SIP/2.0 200", kCallerIp);
		}
		{
			Rig r;
			const std::string raw = timerInvite(to, std::string("pin-long-") + to, kMaxLines);
			ASSERT_LE(raw.size(), kDatagram);
			r.send(raw, kCallerIp);
			longAnswer = r.first("SIP/2.0 200", kCallerIp);
		}
		ASSERT_FALSE(shortAnswer.empty()) << "precondition: " << to << " answers a short INVITE";
		ASSERT_FALSE(longAnswer.empty()) << "a 64-line INVITE to " << to << " was not answered";
		EXPECT_EQ(headerNames(longAnswer), headerNames(shortAnswer))
			<< "the answer to the 64-line INVITE lost lines:\n" << longAnswer;
		const std::string body = bodyOf(longAnswer);
		EXPECT_FALSE(body.empty()) << longAnswer;
		EXPECT_NE(longAnswer.find("\r\nContent-Type: application/sdp\r\n"), std::string::npos) << longAnswer;
		EXPECT_EQ(headerValue(longAnswer, "Content-Length"), std::to_string(body.size())) << longAnswer;
		if (std::string(to) == "555")
		{
			EXPECT_NE(longAnswer.find("\r\nRequire: timer\r\n"), std::string::npos)
				<< "555 grants the session timer (RFC 4028 §9):\n" << longAnswer;
		}
	}
}

// The 400 to a 65-line INVITE is the 64 lines kept plus the PBX's Warning: 65
// lines, built by copy (no re-parse) and stored by the transaction layer.
TEST(HeaderLinePinning, AStoredResponseOfMoreThanSixtyFourLinesIsRetransmittedByteForByte)
{
	Rig r;
	r.send(invite("500", kCallerIp, "600", "pin-retx", kMaxLines + 1), kCallerIp);
	const std::string first = r.first("SIP/2.0 400", kCallerIp);
	ASSERT_NE(first.find("too many header lines"), std::string::npos) << r.dump();
	ASSERT_LT(first.size(), static_cast<size_t>(POCKETDIAL_TX_MSG_BYTES))
		<< "precondition: the transaction layer stores the response whole";
	r.sent.clear();

	// No ACK: Timer G (RFC 3261 §17.2.1) sends it again from the stored bytes
	// once T1 (500 ms) has passed, through tick() -> TransactionLayer::sweep()
	// -> resend(), the path the SIP task runs.
	std::this_thread::sleep_for(std::chrono::milliseconds(700));
	r.handler.forceNextTickForTest();
	r.handler.tick();
	const std::string again = r.first("SIP/2.0 400", kCallerIp);
	ASSERT_FALSE(again.empty()) << "precondition: Timer G fired:\n" << r.dump();
	EXPECT_EQ(again, first);
}

TEST(HeaderLinePinning, AnEmergencyInviteCutOnTheWireIsAnsweredOverTheAnchorWithItsContentType)
{
	Rig r;
	r.handler.setAnchorPlacesRealCallsForTest(true);
	// Its own Content-Type and Content-Length are lines 69 and 70: cut on the wire.
	r.send(invite("500", kCallerIp, "911", "pin-911-anchor", kMaxLines + 6), kCallerIp);
	const std::string ok = r.first("SIP/2.0 200", kCallerIp);
	ASSERT_FALSE(ok.empty()) << "the 911 caller must be answered:\n" << r.dump();
	const std::string body = bodyOf(ok);
	ASSERT_FALSE(body.empty()) << ok;
	EXPECT_NE(ok.find("\r\nContent-Type: application/sdp\r\n"), std::string::npos)
		<< "an SDP answer without the Content-Type the PBX spliced in:\n" << ok;
	const std::string length = headerValue(ok, "Content-Length");
	if (!length.empty()) EXPECT_EQ(length, std::to_string(body.size())) << ok;
}

TEST(HeaderLinePinning, AMessageThePbxBuiltIsReparsedWholeWhateverItsLength)
{
	// 100 lines of 100+ characters: past both the line cap and the 8 KB budget,
	// which may free spare capacity but never a byte of content.
	std::string raw = "SIP/2.0 200 OK\r\n";
	for (int i = 0; i < 100; ++i) raw += "X-Built-" + std::to_string(i) + ": " + std::string(100, 'b') + "\r\n";
	raw += "Content-Length: 0\r\n\r\n";
	const sockaddr_in src = addrFor(kPinIp);

	SipMessage m(std::string(), src);
	for (int i = 0; i < 2; ++i)
	{
		m.reset(raw, src);
		EXPECT_EQ(m.toString(), raw);
	}
	SipMessage copy(std::string(), src);
	copy = m;
	EXPECT_EQ(copy.toString(), raw);

	// Shorter lines into the same buffers: each in-use line now holds spare
	// capacity while the total is still past the budget, so the budget gives
	// lines exact-size buffers. Content must come through untouched.
	std::string shorter = "SIP/2.0 200 OK\r\n";
	for (int i = 0; i < 100; ++i) shorter += "X-Built-" + std::to_string(i) + ": " + std::string(90, 's') + "\r\n";
	shorter += "Content-Length: 0\r\n\r\n";
	m.reset(shorter, src);
	EXPECT_EQ(m.toString(), shorter);
	m.reset(raw, src);
	EXPECT_EQ(m.toString(), raw);
}

// D1: a 2xx whose Record-Route runs past the cut has lost the hop nearest this
// PBX, the route set's FIRST hop once reversed. A partial route set sends every
// in-dialog request to the wrong proxy, so it is not used at all: the ACK goes
// to the carrier, as with no Record-Route.
TEST(HeaderLinePinning, ACarrierAnswerCutThroughItsRecordRouteLeavesNoPartialRouteSet)
{
	TrunkRig b;
	b.handler.handle(fromWire(invite("1001", kHandsetIp, "92025550123", "pin-rr", 12), kHandsetIp));
	const std::string carrierInvite = b.first("INVITE sip:+1", kSbcIp);
	ASSERT_FALSE(carrierInvite.empty()) << "precondition: the call went to the trunk:\n" << b.dump();
	b.sent.clear();

	b.handler.handle(fromWire(carrierAnswerWithRecordRoute(carrierInvite), kSbcIp));
	const std::string ack = b.first("ACK", kSbcIp);
	ASSERT_FALSE(ack.empty()) << "the ACK must go to the carrier, not a hop the cut left first:\n" << b.dump();
	EXPECT_EQ(ack.find("\r\nRoute:"), std::string::npos) << "a route set missing its first hop:\n" << ack;
}

// D1's companion: every datagram cut at the cap is counted, and nothing else.
TEST(HeaderLinePinning, ADatagramCutAtTheCapIsCounted)
{
	Rig r;
	r.send(invite("500", kCallerIp, "600", "pin-count-64", kMaxLines), kCallerIp);
	EXPECT_EQ(r.handler.getHeaderLineCuts(), 0u) << "64 lines are not cut";
	r.send(invite("500", kCallerIp, "600", "pin-count-65", kMaxLines + 1), kCallerIp);
	r.send(hostileResponse("pin-count-resp"), kCalleeIp);
	EXPECT_EQ(r.handler.getHeaderLineCuts(), 2u) << "one request and one response past the cap";
}
