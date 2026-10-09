// Forward100rel_test.cpp — Issue #172 step 3: Require: 100rel on a call the PBX forwards.
//
// RFC 3262 §3: a UAS that receives Require: 100rel MUST send every non-100 provisional
// reliably or answer 420. Main answers 420 to every INVITE but the 777 echo's. With the
// default-off flag (RequestsHandler::setForward100rel) a plain registered-extension to
// registered-extension INVITE is accepted instead: the PBX removes 100rel from the Require
// and Supported of the leg it forwards to the callee, makes the callee's 180 reliable toward
// the caller (Require: 100rel, an RSeq of its own, its own Contact) and answers the caller's
// PRACK itself. Nothing else changes: ring groups, hunt, paging, call forward, dial rules,
// the special extensions, the trunk and all emergency traffic keep the answer they had.
//
// The PBX pushes no Via of its own on relayed requests, so these tests hand it the callee's
// answers directly. A callee that follows RFC 3261 §18.2.2 to the letter answers the caller
// itself and the PBX never sees that 180; the caller then gets the unreliable one.

#include <gtest/gtest.h>

#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <initializer_list>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "CallDetailRecord.hpp"
#include "PoolConfig.hpp"
#include "RequestsHandler.hpp"
#include "Session.hpp"
#include "support/AllocCounter.hpp"

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#else
#include <arpa/inet.h>
#endif

namespace
{
	using Sent = std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>>;

	constexpr const char* kPbx      = "192.168.7.1";
	constexpr const char* kCallerIp = "192.168.7.50";
	constexpr const char* kCalleeIp = "192.168.7.60";
	constexpr const char* kPeerIp   = "192.168.7.61";   // a second registered extension, 610
	constexpr const char* kSbcIp    = "203.0.113.5";    // RFC 5737 TEST-NET-3
	constexpr const char* kCalleeContact = "sip:600@192.168.7.60:5060;line=1";

	sockaddr_in addrFor(const std::string& ip)
	{
		sockaddr_in s{};
		s.sin_family = AF_INET;
		s.sin_addr.s_addr = inet_addr(ip.c_str());
		s.sin_port = htons(5060);
		return s;
	}

	std::shared_ptr<SipMessage> makeRegister(const std::string& ext, const std::string& ip,
	                                          const std::string& contactParams = "")
	{
		const std::string raw =
			"REGISTER sip:server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + ip + ":5060;branch=z9hG4bKr" + ext + "\r\n"
			"From: <sip:" + ext + "@server>;tag=rt" + ext + "\r\n"
			"To: <sip:" + ext + "@server>\r\n"
			"Call-ID: reg-" + ext + "\r\n"
			"CSeq: 1 REGISTER\r\n"
			"Contact: <sip:" + ext + "@" + ip + ":5060" + contactParams + ">;expires=3600\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addrFor(ip));
	}

	// extraHeaders is inserted verbatim, one "Name: value\r\n" per line.
	std::shared_ptr<SipMessage> makeInvite(const std::string& fromExt, const std::string& toExt,
	                                        const std::string& srcIp, const std::string& callId,
	                                        const std::string& extraHeaders = "",
	                                        const std::string& fromUser = "")
	{
		const std::string from = fromUser.empty() ? fromExt : fromUser;
		const std::string body =
			"v=0\r\n"
			"o=- 0 0 IN IP4 " + srcIp + "\r\n"
			"s=-\r\n"
			"c=IN IP4 " + srcIp + "\r\n"
			"t=0 0\r\n"
			"m=audio 10000 RTP/AVP 0\r\n"
			"a=rtpmap:0 PCMU/8000\r\n";
		const std::string raw =
			"INVITE sip:" + toExt + "@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + srcIp + ":5060;branch=z9hG4bKi" + callId + "\r\n"
			"From: <sip:" + from + "@server>;tag=ft" + callId + "\r\n"
			"To: <sip:" + toExt + "@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Max-Forwards: 70\r\n"
			"Contact: <sip:" + from + "@" + srcIp + ":5060>\r\n" +
			extraHeaders +
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		return RequestsHandler::getMessageFromPool(raw, addrFor(srcIp));
	}

	// The caller's PRACK for the callee's reliable 180, addressed where that 180's Contact says.
	std::shared_ptr<SipMessage> makePrack(const std::string& callId, const std::string& toTag,
	                                       const std::string& rack, int cseq = 2,
	                                       const std::string& branchTag = "p",
	                                       const std::string& srcIp = kCallerIp,
	                                       const std::string& fromExt = "500", const std::string& toExt = "600")
	{
		const std::string raw =
			"PRACK sip:" + toExt + "@" + std::string(kPbx) + ":5060;transport=UDP SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + srcIp + ":5060;branch=z9hG4bK" + branchTag + callId + "\r\n"
			"From: <sip:" + fromExt + "@server>;tag=ft" + callId + "\r\n"
			"To: <sip:" + toExt + "@server>;tag=" + toTag + "\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: " + std::to_string(cseq) + " PRACK\r\n" +
			(rack.empty() ? std::string{} : "RAck: " + rack + "\r\n") +
			"Max-Forwards: 70\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addrFor(srcIp));
	}

	std::shared_ptr<SipMessage> makeInDialog(const std::string& method, const std::string& callId,
	                                          const std::string& toTag, int cseq, const std::string& srcIp = kCallerIp,
	                                          const std::string& fromExt = "500", const std::string& toExt = "600")
	{
		const std::string raw =
			method + " sip:" + toExt + "@" + std::string(kPbx) + ":5060 SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + srcIp + ":5060;branch=z9hG4bK" + method + callId + "\r\n"
			"From: <sip:" + fromExt + "@server>;tag=ft" + callId + "\r\n"
			"To: <sip:" + toExt + "@server>" + (toTag.empty() ? std::string{} : ";tag=" + toTag) + "\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: " + std::to_string(cseq) + " " + method + "\r\n"
			"Max-Forwards: 70\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addrFor(srcIp));
	}

	// A CANCEL carries the INVITE's branch and CSeq number (RFC 3261 §9.1).
	std::shared_ptr<SipMessage> makeCancel(const std::string& callId)
	{
		const std::string raw =
			"CANCEL sip:600@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + std::string(kCallerIp) + ":5060;branch=z9hG4bKi" + callId + "\r\n"
			"From: <sip:500@server>;tag=ft" + callId + "\r\n"
			"To: <sip:600@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 CANCEL\r\n"
			"Max-Forwards: 70\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addrFor(kCallerIp));
	}

	std::string rawOf(const std::shared_ptr<SipMessage>& m) { return m ? m->toString() : std::string{}; }

	std::string headPart(const std::string& raw) { return raw.substr(0, raw.find("\r\n\r\n")); }

	std::string firstLine(const std::string& raw) { return raw.substr(0, raw.find("\r\n")); }

	std::string lower(std::string s)
	{
		for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
		return s;
	}

	std::string trim(const std::string& s)
	{
		size_t a = 0, b = s.size();
		while (a < b && (s[a] == ' ' || s[a] == '\t')) ++a;
		while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t')) --b;
		return s.substr(a, b - a);
	}

	// The values of every header line whose name is one of `names` (case-insensitive).
	std::vector<std::string> valuesOf(const std::string& raw, std::initializer_list<const char*> names)
	{
		std::vector<std::string> out;
		const std::string head = headPart(raw);
		size_t pos = head.find("\r\n");
		while (pos != std::string::npos)
		{
			const size_t start = pos + 2;
			const size_t end = head.find("\r\n", start);
			const std::string line = head.substr(start, end == std::string::npos ? std::string::npos : end - start);
			pos = end;
			const size_t colon = line.find(':');
			if (colon == std::string::npos) continue;
			const std::string name = lower(trim(line.substr(0, colon)));
			for (const char* n : names)
			{
				if (name == n) out.push_back(trim(line.substr(colon + 1)));
			}
		}
		return out;
	}

	// First value of header `name`, or "".
	std::string headerValue(const std::string& raw, const char* name)
	{
		const auto v = valuesOf(raw, {name});
		return v.empty() ? std::string{} : v.front();
	}

	// True when any of `names` carries `tag` as a comma-separated token (case-insensitive).
	bool hasToken(const std::string& raw, std::initializer_list<const char*> names, const std::string& tag)
	{
		for (const std::string& value : valuesOf(raw, names))
		{
			size_t at = 0;
			while (at <= value.size())
			{
				const size_t comma = value.find(',', at);
				const std::string token = lower(trim(value.substr(at, comma == std::string::npos ? std::string::npos : comma - at)));
				if (token == tag) return true;
				if (comma == std::string::npos) break;
				at = comma + 1;
			}
		}
		return false;
	}

	std::string toTagOf(const std::string& raw)
	{
		const std::string to = headerValue(raw, "to");
		const size_t at = to.find("tag=");
		return at == std::string::npos ? std::string{} : to.substr(at + 4);
	}

	// First message sent to `ip` whose raw text starts with `prefix` and contains `needle`, or "".
	std::string firstTo(const Sent& sent, const std::string& ip, const std::string& prefix,
	                    const std::string& needle = "")
	{
		const uint32_t want = inet_addr(ip.c_str());
		for (const auto& [addr, msg] : sent)
		{
			if (addr.sin_addr.s_addr != want) continue;
			const std::string raw = rawOf(msg);
			if (raw.rfind(prefix, 0) == 0 && raw.find(needle) != std::string::npos) return raw;
		}
		return {};
	}

	size_t countTo(const Sent& sent, const std::string& ip, const std::string& prefix,
	               const std::string& needle = "")
	{
		const uint32_t want = inet_addr(ip.c_str());
		size_t n = 0;
		for (const auto& [addr, msg] : sent)
		{
			if (addr.sin_addr.s_addr != want) continue;
			const std::string raw = rawOf(msg);
			if (raw.rfind(prefix, 0) == 0 && raw.find(needle) != std::string::npos) ++n;
		}
		return n;
	}

	bool anySent(const Sent& sent, const std::string& text)
	{
		for (const auto& [addr, msg] : sent)
		{
			(void)addr;
			if (rawOf(msg).find(text) != std::string::npos) return true;
		}
		return false;
	}

	size_t countOutsideTheCaller(const Sent& sent)
	{
		size_t n = 0;
		const uint32_t caller = inet_addr(kCallerIp);
		for (const auto& [addr, msg] : sent)
		{
			if (msg && addr.sin_addr.s_addr != caller) ++n;
		}
		return n;
	}

	// ";tag=<token>" -> ";tag=T": the PBX mints its own To tags, which differ run to run.
	std::string normalizeTags(std::string s)
	{
		size_t at = 0;
		while ((at = s.find(";tag=", at)) != std::string::npos)
		{
			size_t end = at + 5;
			while (end < s.size() && s[end] != '\r' && s[end] != ';' && s[end] != '>' && s[end] != ' ') ++end;
			s.replace(at + 5, end - (at + 5), "T");
			at += 6;
		}
		return s;
	}

	// ";branch=<token>" -> ";branch=B": the Via branch of a request the PBX originates (its BYE) is random.
	std::string normalizeBranches(std::string s)
	{
		size_t at = 0;
		while ((at = s.find(";branch=", at)) != std::string::npos)
		{
			size_t end = at + 8;
			while (end < s.size() && s[end] != '\r' && s[end] != ';' && s[end] != '>' && s[end] != ' ') ++end;
			s.replace(at + 8, end - (at + 8), "B");
			at += 9;
		}
		return s;
	}

	std::string transcript(const Sent& sent)
	{
		std::string out;
		for (const auto& [addr, msg] : sent)
		{
			out += std::string(inet_ntoa(addr.sin_addr)) + " <- " + normalizeBranches(normalizeTags(rawOf(msg))) + "\n----\n";
		}
		return out;
	}

	struct Rig
	{
		Sent sent;
		RequestsHandler handler{kPbx, 5060,
			[this](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
				sent.emplace_back(addr, std::move(msg));
			}};

		explicit Rig(bool flag = false)
		{
			handler.handle(makeRegister("500", kCallerIp));
			handler.handle(makeRegister("600", kCalleeIp, ";line=1"));
			handler.handle(makeRegister("610", kPeerIp));
			if (flag) handler.setForward100rel(true);
			sent.clear();
		}

		// The callee's answer to the INVITE it was relayed (RFC 3261 §8.2.6.2). A 2xx carries SDP, as
		// onOk() requires.
		void calleeAnswers(const std::string& relayed, const std::string& status, const std::string& toTag,
		                   const std::string& extra = "", bool sdp180 = false,
		                   const std::string& calleeIp = kCalleeIp, const std::string& calleeExt = "600")
		{
			handler.handle(calleeMessage(relayed, status, toTag, extra, sdp180, calleeIp, calleeExt));
		}

		// The same answer as a message that has not been handled yet.
		static std::shared_ptr<SipMessage> calleeMessage(const std::string& relayed, const std::string& status,
		                                                  const std::string& toTag, const std::string& extra = "",
		                                                  bool sdp180 = false, const std::string& calleeIp = kCalleeIp,
		                                                  const std::string& calleeExt = "600")
		{
			std::string to = "To: " + headerValue(relayed, "to");
			if (to.find("tag=") == std::string::npos) to += ";tag=" + toTag;
			const bool withSdp = (status.rfind("200", 0) == 0 && headerValue(relayed, "cseq").find("INVITE") != std::string::npos) ||
				sdp180;
			const std::string body = withSdp
				? "v=0\r\no=- 0 0 IN IP4 192.168.7.60\r\ns=-\r\nc=IN IP4 192.168.7.60\r\nt=0 0\r\n"
				  "m=audio 20000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
				: std::string{};
			const std::string raw =
				"SIP/2.0 " + status + "\r\n"
				"Via: " + headerValue(relayed, "via") + "\r\n"
				"From: " + headerValue(relayed, "from") + "\r\n" +
				to + "\r\n"
				"Call-ID: " + headerValue(relayed, "call-id") + "\r\n"
				"CSeq: " + headerValue(relayed, "cseq") + "\r\n"
				"Contact: <sip:" + calleeExt + "@" + calleeIp + ":5060;line=1>\r\n" +
				extra +
				(withSdp ? "Content-Type: application/sdp\r\n" : "") +
				"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
			return RequestsHandler::getMessageFromPool(raw, addrFor(calleeIp));
		}
	};

	struct Call
	{
		std::string id;
		std::string relayed;   // the INVITE the callee received
	};

	Call startCall(Rig& rig, const std::string& id, const std::string& extra, const std::string& to = "600")
	{
		rig.handler.handle(makeInvite("500", to, kCallerIp, id, extra));
		return {id, firstTo(rig.sent, to == "600" ? kCalleeIp : kPeerIp, "INVITE ")};
	}

	const std::string kRequire = "Require: 100rel\r\n";
}

// ── The flag ──────────────────────────────────────────────────────────────────

// The shipped default is read from the engine, not assumed: nothing sets the flag at construction.
TEST(Forward100rel, TheShippedDefaultIsOff)
{
	Rig rig;
	EXPECT_FALSE(rig.handler.getForward100rel());
	rig.handler.setForward100rel(true);
	EXPECT_TRUE(rig.handler.getForward100rel());
	rig.handler.setForward100rel(false);
	EXPECT_FALSE(rig.handler.getForward100rel());
}

// Guard, passes on main: with the flag off the gate is the one #953 left. The 420 text is pinned as it
// was captured from main's code, so an off path that drifts by a byte fails here.
TEST(Forward100rel, FlagOffAnswers420ToAnExtensionCallVerbatim)
{
	Rig rig;
	rig.handler.handle(makeInvite("500", "600", kCallerIp, "off-420", kRequire));

	ASSERT_EQ(rig.sent.size(), 1u) << transcript(rig.sent);
	EXPECT_EQ(normalizeTags(rawOf(rig.sent[0].second)),
		"SIP/2.0 420 Bad Extension\r\n"
		"Via: SIP/2.0/UDP 192.168.7.50:5060;branch=z9hG4bKioff-420;received=192.168.7.50\r\n"
		"From: <sip:500@server>;tag=T\r\n"
		"To: <sip:600@server>\r\n"
		"Call-ID: off-420\r\n"
		"CSeq: 1 INVITE\r\n"
		"Max-Forwards: 70\r\n"
		"Contact: <sip:500@192.168.7.50:5060>\r\n"
		"Content-Type: application/sdp\r\n"
		"Unsupported: 100rel\r\n"
		"Content-Length: 0\r\n\r\n")
		<< "main's wire answer to an extension call with Require: 100rel";
	EXPECT_EQ(countOutsideTheCaller(rig.sent), 0u) << "nothing is relayed to the callee";
}

// Guard, passes on main: an INVITE that does not require 100rel (Supported: 100rel is only an offer) is
// forwarded and answered byte for byte the same with the flag off and on.
TEST(Forward100rel, FlagOffAndOnGiveTheSameWireWhenTheCallerDoesNotRequire100rel)
{
	auto run = [](bool flag) {
		Rig rig(flag);
		const Call call = startCall(rig, "same-plain",
			"Supported: 100rel, timer\r\nRequire: timer\r\nSession-Expires: 1800\r\n");
		rig.calleeAnswers(call.relayed, "180 Ringing", "ct1");
		rig.calleeAnswers(call.relayed, "200 OK", "ct1");
		rig.handler.handle(makeInDialog("ACK", "same-plain", "ct1", 1));
		rig.handler.handle(makeInDialog("BYE", "same-plain", "ct1", 2));
		return transcript(rig.sent);
	};
	const std::string off = run(false);
	const std::string on = run(true);
	EXPECT_EQ(off, on);
	EXPECT_NE(off.find("SIP/2.0 180 Ringing"), std::string::npos) << off;
	EXPECT_NE(off.find("Supported: 100rel, timer"), std::string::npos)
		<< "an offer of 100rel is left alone on the forwarded leg";
}

// ── Point 1: the forwarded leg ────────────────────────────────────────────────

// Red on main: the gate answers 420 and nothing is forwarded.
TEST(Forward100rel, ForwardedLegCarriesNo100relInRequireAndKeepsTheOtherTags)
{
	struct Row
	{
		const char* what;
		std::string lines;    // the caller's Require lines
		std::string expect;   // the Require values left on the leg, joined by '|'
	};
	const std::vector<Row> rows = {
		{"only tag",              "Require: 100rel\r\n",                         ""},
		{"first of two",          "Require: 100rel, timer\r\n",                  "timer"},
		{"last of two",           "Require: timer, 100rel\r\n",                  "timer"},
		{"middle of three",       "Require: timer ,100rel , replaces\r\n",       "timer,replaces"},
		{"upper case",            "Require: 100REL\r\n",                         ""},
		{"two lines",             "Require: 100rel\r\nRequire: timer\r\n",       "timer"},
		{"tag on both lines",     "Require: 100rel\r\nRequire: replaces, 100rel\r\n", "replaces"},
	};
	int n = 0;
	for (const Row& row : rows)
	{
		SCOPED_TRACE(row.what);
		Rig rig(true);
		const Call call = startCall(rig, "strip" + std::to_string(n++), row.lines);

		ASSERT_FALSE(call.relayed.empty()) << "the INVITE is forwarded to the callee\n" << transcript(rig.sent);
		EXPECT_EQ(firstLine(call.relayed), std::string("INVITE ") + kCalleeContact + " SIP/2.0")
			<< "the leg is addressed at the Contact the callee registered";
		EXPECT_FALSE(hasToken(call.relayed, {"require"}, "100rel"));
		std::string left;
		for (const std::string& v : valuesOf(call.relayed, {"require"}))
		{
			std::string squeezed;
			for (char c : v) if (c != ' ') squeezed += c;
			left += (left.empty() ? "" : ",") + squeezed;
		}
		EXPECT_EQ(left, row.expect);
		EXPECT_FALSE(anySent(rig.sent, "420 Bad Extension")) << "the caller is not refused";
	}
}

// Red on main. RFC 3262 §3: with neither Supported nor Require naming 100rel the callee MUST NOT send a
// reliable provisional, and the PBX could not PRACK one, so the offer goes too (compact form included).
TEST(Forward100rel, ForwardedLegAlsoLoses100relFromSupportedAndKeepsTheOtherTags)
{
	struct Row
	{
		const char* what;
		std::string lines;
		std::string expect;   // Supported values left on the leg, joined by '|', spaces squeezed
	};
	const std::vector<Row> rows = {
		{"long form",           "Supported: replaces, 100rel, timer\r\n", "replaces,timer"},
		{"compact form",        "k: 100rel, timer\r\n",                   "timer"},
		{"only tag",            "Supported: 100rel\r\n",                  ""},
		{"absent",              "",                                       ""},
	};
	int n = 0;
	for (const Row& row : rows)
	{
		SCOPED_TRACE(row.what);
		Rig rig(true);
		const Call call = startCall(rig, "sup" + std::to_string(n++), kRequire + row.lines);

		ASSERT_FALSE(call.relayed.empty()) << transcript(rig.sent);
		EXPECT_FALSE(hasToken(call.relayed, {"supported", "k"}, "100rel"));
		std::string left;
		for (const std::string& v : valuesOf(call.relayed, {"supported", "k"}))
		{
			std::string squeezed;
			for (char c : v) if (c != ' ') squeezed += c;
			left += (left.empty() ? "" : ",") + squeezed;
		}
		EXPECT_EQ(left, row.expect);
	}
}

// Red on main (that one 420s the whole INVITE): another tag the PBX does not honour still refuses the call,
// naming that tag and not 100rel, as before #172.
TEST(Forward100rel, AnotherUnknownRequireTagStillRefusesTheCall)
{
	Rig rig(true);
	rig.handler.handle(makeInvite("500", "600", kCallerIp, "unk", "Require: 100rel, path\r\n"));

	EXPECT_TRUE(anySent(rig.sent, "420 Bad Extension"));
	EXPECT_TRUE(anySent(rig.sent, "Unsupported: path"));
	EXPECT_FALSE(anySent(rig.sent, "Unsupported: 100rel"));
	EXPECT_EQ(countOutsideTheCaller(rig.sent), 0u);
}

// Guard, passes on main. Proxy-Require is not 100rel's place (RFC 3262 §4).
TEST(Forward100rel, ProxyRequire100relIsStillRefused)
{
	Rig rig(true);
	rig.handler.handle(makeInvite("500", "600", kCallerIp, "pxy", "Proxy-Require: 100rel\r\n"));

	EXPECT_TRUE(anySent(rig.sent, "420 Bad Extension"));
	EXPECT_TRUE(anySent(rig.sent, "Unsupported: 100rel"));
	EXPECT_EQ(countOutsideTheCaller(rig.sent), 0u);
}

// Red on main. RFC 3262 §4 puts 100rel in no request but INVITE, so a CANCEL naming it would be refused by a
// strict callee that then keeps ringing. The caller's own CANCEL is relayed as it came; the one the PBX
// builds when the callee does not answer (voicemail's, here) is a copy of the stored INVITE, which is why
// the tag leaves that copy and not only the leg.
TEST(Forward100rel, CancelsCarryNo100rel)
{
	{
		SCOPED_TRACE("the caller cancels");
		Rig rig(true);
		const Call call = startCall(rig, "cnl", kRequire + "Supported: 100rel\r\n");
		ASSERT_FALSE(call.relayed.empty()) << transcript(rig.sent);
		rig.sent.clear();

		rig.handler.handle(makeCancel("cnl"));

		const std::string cancel = firstTo(rig.sent, kCalleeIp, "CANCEL ");
		ASSERT_FALSE(cancel.empty()) << "the callee is told to stop ringing\n" << transcript(rig.sent);
		EXPECT_FALSE(hasToken(cancel, {"require", "supported", "k"}, "100rel"));
	}
	{
		SCOPED_TRACE("nobody answers and voicemail takes the call");
		Rig rig(true);
		rig.handler.setVoicemail("600", true);
		const Call call = startCall(rig, "cnl-vm", kRequire + "Supported: 100rel\r\n");
		ASSERT_FALSE(call.relayed.empty()) << transcript(rig.sent);
		const auto session = rig.handler.getSession("Call-ID: cnl-vm");
		ASSERT_TRUE(session.has_value());
		session.value()->armRingTimer(std::chrono::steady_clock::now() - std::chrono::seconds(1));
		rig.sent.clear();

		rig.handler.forceNextTickForTest();
		rig.handler.tick();

		const std::string cancel = firstTo(rig.sent, kCalleeIp, "CANCEL ");
		ASSERT_FALSE(cancel.empty()) << "the ringing callee is cancelled before voicemail answers\n" << transcript(rig.sent);
		EXPECT_FALSE(hasToken(cancel, {"require", "supported", "k"}, "100rel"));
	}
}

// ── Point 2: a reliable 180 toward the caller, PRACK answered here ────────────

// Red on main.
TEST(Forward100rel, CalleeUnreliable180ReachesTheCallerAsAReliableOne)
{
	Rig rig(true);
	const Call call = startCall(rig, "rel", kRequire);
	ASSERT_FALSE(call.relayed.empty()) << transcript(rig.sent);
	rig.sent.clear();

	rig.calleeAnswers(call.relayed, "180 Ringing", "ct1");

	const std::string ringing = firstTo(rig.sent, kCallerIp, "SIP/2.0 180 Ringing");
	ASSERT_FALSE(ringing.empty()) << transcript(rig.sent);
	EXPECT_TRUE(hasToken(ringing, {"require"}, "100rel")) << "RFC 3262 §3: a reliable provisional MUST contain Require: 100rel";
	EXPECT_EQ(headerValue(ringing, "rseq"), "1") << "the first RSeq is in 1..2**31-1";
	EXPECT_EQ(toTagOf(ringing), "ct1") << "the callee's dialog identity is the caller's";
	EXPECT_NE(headerValue(ringing, "contact").find("sip:600@" + std::string(kPbx) + ":5060"), std::string::npos)
		<< "the PRACK must come to the PBX, not to the callee, which never sent this provisional reliably";
	EXPECT_EQ(headerValue(ringing, "content-length"), "0");
	EXPECT_EQ(countTo(rig.sent, kCalleeIp, ""), 0u) << "nothing goes back to the callee";
}

// Red on main. A callee that writes its Contact in compact form (m:) gets the PBX's Contact in its place, not
// beside it: two Contact lines would leave the caller guessing where to send the PRACK.
TEST(Forward100rel, ACompactContactOnTheCalleesProvisionalIsReplacedNotDuplicated)
{
	Rig rig(true);
	const Call call = startCall(rig, "cmp", kRequire);
	ASSERT_FALSE(call.relayed.empty()) << transcript(rig.sent);
	rig.sent.clear();
	std::string raw = Rig::calleeMessage(call.relayed, "180 Ringing", "ct1")->toString();
	const size_t at = raw.find("\r\nContact:");
	ASSERT_NE(at, std::string::npos);
	raw.replace(at + 2, 8, "m:");

	rig.handler.handle(RequestsHandler::getMessageFromPool(raw, addrFor(kCalleeIp)));

	const std::string ringing = firstTo(rig.sent, kCallerIp, "SIP/2.0 180 Ringing");
	ASSERT_FALSE(ringing.empty()) << transcript(rig.sent);
	EXPECT_EQ(valuesOf(ringing, {"contact", "m"}).size(), 1u) << ringing;
	EXPECT_EQ(headerValue(ringing, "contact"), "<sip:600@192.168.7.1:5060;transport=UDP>");
}

// Red on main. A 180 that carries a session description would have to hold the final response until its
// PRACK (RFC 3262 §3). The relay does not: it sends the 180 reliably without the body.
TEST(Forward100rel, A180WithEarlyMediaIsRelayedReliablyWithoutItsBody)
{
	Rig rig(true);
	const Call call = startCall(rig, "sdp180", kRequire);
	rig.sent.clear();

	rig.calleeAnswers(call.relayed, "180 Ringing", "ct1", "", /*sdp180=*/true);

	const std::string ringing = firstTo(rig.sent, kCallerIp, "SIP/2.0 180 Ringing");
	ASSERT_FALSE(ringing.empty()) << transcript(rig.sent);
	EXPECT_EQ(headerValue(ringing, "rseq"), "1");
	EXPECT_EQ(ringing.find("\r\n\r\n") + 4, ringing.size()) << "no body";
	EXPECT_EQ(headerValue(ringing, "content-length"), "0");
}

// Guard, passes on main: a caller that only offers 100rel is not touched.
TEST(Forward100rel, ACallerThatOnlyOffers100relGetsTheCalleesPlain180AndNoPrackAnswer)
{
	Rig rig(true);
	const Call call = startCall(rig, "offer", "Supported: 100rel\r\n");
	ASSERT_FALSE(call.relayed.empty());
	EXPECT_TRUE(hasToken(call.relayed, {"supported"}, "100rel")) << "the offer reaches the callee untouched";
	rig.sent.clear();

	rig.calleeAnswers(call.relayed, "180 Ringing", "ct1");
	const std::string ringing = firstTo(rig.sent, kCallerIp, "SIP/2.0 180 Ringing");
	ASSERT_FALSE(ringing.empty());
	EXPECT_EQ(headerValue(ringing, "rseq"), "");
	EXPECT_FALSE(hasToken(ringing, {"require"}, "100rel"));
	EXPECT_NE(headerValue(ringing, "contact").find(kCalleeIp), std::string::npos) << "relayed as before";

	rig.sent.clear();
	rig.handler.handle(makePrack("offer", "ct1", "1 1 INVITE"));
	EXPECT_EQ(rig.sent.size(), 0u) << "a relayed call's PRACK is the callee's to answer, not the PBX's";
}

// Red on main.
TEST(Forward100rel, CallersPrackIsAnsweredHereAndNeverRelayed)
{
	Rig rig(true);
	const Call call = startCall(rig, "ack1", kRequire);
	rig.calleeAnswers(call.relayed, "180 Ringing", "ct1");
	rig.sent.clear();

	rig.handler.handle(makePrack("ack1", "ct1", "1 1 INVITE"));

	const std::string ok = firstTo(rig.sent, kCallerIp, "SIP/2.0 200 OK", "CSeq: 2 PRACK");
	ASSERT_FALSE(ok.empty()) << "RFC 3262 §3: a matching PRACK MUST be answered 2xx\n" << transcript(rig.sent);
	EXPECT_EQ(headerValue(ok, "rack"), "");
	EXPECT_EQ(countTo(rig.sent, kCalleeIp, ""), 0u) << "the callee never offered 100rel and is never sent a PRACK";
	EXPECT_EQ(rig.sent.size(), 1u);
}

// Red on main. RFC 3261 §17.2.3: a retransmitted PRACK (same branch, same CSeq) is answered with the same 200
// from the server transaction, not run again, which would draw a 481 for the provisional it already
// acknowledged. The echo has the same guarantee (Prack100rel).
TEST(Forward100rel, ARetransmittedPrackGetsTheSame200AndRunsNothingAgain)
{
	Rig rig(true);
	const Call call = startCall(rig, "rtx", kRequire);
	rig.calleeAnswers(call.relayed, "180 Ringing", "ct1");
	rig.handler.handle(makePrack("rtx", "ct1", "1 1 INVITE"));
	const std::string first = firstTo(rig.sent, kCallerIp, "SIP/2.0 200 OK", "CSeq: 2 PRACK");
	ASSERT_FALSE(first.empty()) << transcript(rig.sent);
	rig.sent.clear();

	rig.handler.handle(makePrack("rtx", "ct1", "1 1 INVITE"));   // the same bytes again

	EXPECT_EQ(firstTo(rig.sent, kCallerIp, "SIP/2.0 200 OK", "CSeq: 2 PRACK"), first);
	EXPECT_EQ(rig.sent.size(), 1u) << "answered from the cache and nothing else is sent\n" << transcript(rig.sent);
	EXPECT_FALSE(anySent(rig.sent, "SIP/2.0 481"));
}

// Red on main: RFC 3262 §3, a PRACK matching no unacknowledged reliable provisional gets 481, and a
// refused one changes nothing, so the right PRACK still matches afterwards.
TEST(Forward100rel, PrackThatMatchesNothingGets481AndLeavesTheProvisionalPending)
{
	struct Row
	{
		const char* what;
		std::string rack;
	};
	const std::vector<Row> rows = {
		{"wrong RSeq",            "2 1 INVITE"},
		{"RSeq zero",             "0 1 INVITE"},
		{"wrong INVITE CSeq",     "1 2 INVITE"},
		{"wrong method",          "1 1 BYE"},
		{"method missing",        "1 1"},
		{"RSeq not a number",     "x 1 INVITE"},
		{"RAck missing",          ""},
		{"trailing token",        "1 1 INVITE extra"},
	};
	int n = 0;
	for (const Row& row : rows)
	{
		SCOPED_TRACE(row.what);
		const std::string id = "bad" + std::to_string(n++);
		Rig rig(true);
		const Call call = startCall(rig, id, kRequire);
		rig.calleeAnswers(call.relayed, "180 Ringing", "ct1");
		rig.sent.clear();

		rig.handler.handle(makePrack(id, "ct1", row.rack));
		EXPECT_FALSE(firstTo(rig.sent, kCallerIp, "SIP/2.0 481", "CSeq: 2 PRACK").empty()) << transcript(rig.sent);
		EXPECT_TRUE(firstTo(rig.sent, kCallerIp, "SIP/2.0 200 OK", "CSeq: 2 PRACK").empty());
		EXPECT_EQ(countTo(rig.sent, kCalleeIp, ""), 0u);

		rig.sent.clear();
		rig.handler.handle(makePrack(id, "ct1", "1 1 INVITE", 3, "q"));
		EXPECT_FALSE(firstTo(rig.sent, kCallerIp, "SIP/2.0 200 OK", "CSeq: 3 PRACK").empty())
			<< "a refused PRACK must leave the reliable provisional pending";
	}
}

// Red on main: a PRACK before any reliable provisional was sent, and a second one for an RSeq already
// acknowledged, match nothing (RFC 3262 §3).
TEST(Forward100rel, PrackWithNothingPendingGets481)
{
	{
		SCOPED_TRACE("before the callee rang");
		Rig rig(true);
		startCall(rig, "none1", kRequire);
		rig.sent.clear();
		rig.handler.handle(makePrack("none1", "ct1", "1 1 INVITE"));
		EXPECT_FALSE(firstTo(rig.sent, kCallerIp, "SIP/2.0 481", "CSeq: 2 PRACK").empty()) << transcript(rig.sent);
	}
	{
		SCOPED_TRACE("after the first PRACK matched");
		Rig rig(true);
		const Call call = startCall(rig, "none2", kRequire);
		rig.calleeAnswers(call.relayed, "180 Ringing", "ct1");
		rig.handler.handle(makePrack("none2", "ct1", "1 1 INVITE"));
		rig.sent.clear();
		rig.handler.handle(makePrack("none2", "ct1", "1 1 INVITE", 3, "q"));
		EXPECT_FALSE(firstTo(rig.sent, kCallerIp, "SIP/2.0 481", "CSeq: 3 PRACK").empty()) << transcript(rig.sent);
	}
}

// Red on main. RFC 3262 §3: no second reliable provisional until the first is acknowledged, and then the
// RSeq is one higher.
TEST(Forward100rel, SecondProvisionalWaitsForTheFirstPrackAndThenCarriesTheNextRSeq)
{
	Rig rig(true);
	const Call call = startCall(rig, "two", kRequire);
	rig.sent.clear();
	rig.calleeAnswers(call.relayed, "180 Ringing", "ct1");
	rig.calleeAnswers(call.relayed, "180 Ringing", "ct1");
	EXPECT_EQ(countTo(rig.sent, kCallerIp, "SIP/2.0 180 Ringing"), 1u)
		<< "the second 180 is not sent while the first is unacknowledged";

	rig.handler.handle(makePrack("two", "ct1", "1 1 INVITE"));
	rig.sent.clear();
	rig.calleeAnswers(call.relayed, "180 Ringing", "ct1");

	const std::string next = firstTo(rig.sent, kCallerIp, "SIP/2.0 180 Ringing");
	ASSERT_FALSE(next.empty());
	EXPECT_EQ(headerValue(next, "rseq"), "2");
	rig.sent.clear();
	rig.handler.handle(makePrack("two", "ct1", "2 1 INVITE", 3, "q"));
	EXPECT_FALSE(firstTo(rig.sent, kCallerIp, "SIP/2.0 200 OK", "CSeq: 3 PRACK").empty());
}

// Red on main (Rule 6 and the fail-open source check): while the call rings dest is unset, and
// isDialogSourceAuthorized() lets any address through then. A PRACK from a third address is not answered
// and does not retire the provisional.
TEST(Forward100rel, PrackFromAThirdAddressWhileRingingStaysSilentAndConsumesNothing)
{
	Rig rig(true);
	const Call call = startCall(rig, "forge", kRequire);
	rig.calleeAnswers(call.relayed, "180 Ringing", "ct1");
	rig.sent.clear();

	rig.handler.handle(makePrack("forge", "ct1", "1 1 INVITE", 2, "x", "192.168.7.99"));
	EXPECT_EQ(rig.sent.size(), 0u) << transcript(rig.sent);

	rig.handler.handle(makePrack("forge", "ct1", "1 1 INVITE", 3, "q"));
	EXPECT_FALSE(firstTo(rig.sent, kCallerIp, "SIP/2.0 200 OK", "CSeq: 3 PRACK").empty())
		<< "the forged PRACK must not have consumed the pending provisional";
}

// Red on main. The 180 carries no session description, so RFC 3262 §3 lets the final response go without
// waiting for the PRACK; the call is answered, and the late PRACK still gets its 200.
TEST(Forward100rel, FinalResponseIsNotHeldForThePrack)
{
	Rig rig(true);
	const Call call = startCall(rig, "fin", kRequire);
	rig.calleeAnswers(call.relayed, "180 Ringing", "ct1");
	const std::string ringing = firstTo(rig.sent, kCallerIp, "SIP/2.0 180 Ringing");
	rig.sent.clear();

	rig.calleeAnswers(call.relayed, "200 OK", "ct1");

	const std::string ok = firstTo(rig.sent, kCallerIp, "SIP/2.0 200 OK", "CSeq: 1 INVITE");
	ASSERT_FALSE(ok.empty()) << transcript(rig.sent);
	EXPECT_FALSE(hasToken(ok, {"require"}, "100rel"));
	EXPECT_EQ(headerValue(ok, "rseq"), "");
	// The 180 and the 200 present the callee the same way, so the dialog's remote target does not change
	// under the caller between them (the 180's is written in place, the 200's by buildContact()).
	EXPECT_EQ(headerValue(ringing, "contact"), headerValue(ok, "contact"));
	EXPECT_EQ(headerValue(ok, "contact"), "<sip:600@192.168.7.1:5060;transport=UDP>");
	const auto session = rig.handler.getSession("Call-ID: fin");
	ASSERT_TRUE(session.has_value());
	EXPECT_EQ(session.value()->getState(), Session::State::Connected);

	rig.sent.clear();
	rig.handler.handle(makePrack("fin", "ct1", "1 1 INVITE"));
	EXPECT_FALSE(firstTo(rig.sent, kCallerIp, "SIP/2.0 200 OK", "CSeq: 2 PRACK").empty())
		<< "RFC 3262 §3: the UAS MUST be prepared to process PRACKs after the final response";
}

// Guard, passes on main: no new reliable provisional once the call is answered (RFC 3262 §3).
TEST(Forward100rel, ALate180AfterTheAnswerIsNotMadeReliable)
{
	Rig rig(true);
	const Call call = startCall(rig, "late", kRequire);
	rig.calleeAnswers(call.relayed, "200 OK", "ct1");
	rig.sent.clear();

	rig.calleeAnswers(call.relayed, "180 Ringing", "ct1");

	EXPECT_EQ(countTo(rig.sent, kCallerIp, "SIP/2.0 180", "RSeq:"), 0u) << transcript(rig.sent);
}

// Red on main: the dialog is torn down once, so a PRACK after the BYE finds no session and stays silent.
TEST(Forward100rel, PrackAfterTheCallEndedStaysSilent)
{
	Rig rig(true);
	const Call call = startCall(rig, "gone", kRequire);
	rig.calleeAnswers(call.relayed, "180 Ringing", "ct1");
	rig.calleeAnswers(call.relayed, "200 OK", "ct1");
	rig.handler.handle(makeInDialog("ACK", "gone", "ct1", 1));
	rig.handler.handle(makeInDialog("BYE", "gone", "ct1", 3));
	const std::string bye = firstTo(rig.sent, kCalleeIp, "BYE ");
	ASSERT_FALSE(bye.empty()) << "the BYE goes on to the callee";
	rig.calleeAnswers(bye, "200 OK", "ct1");   // the session is released when the callee has answered it
	ASSERT_FALSE(rig.handler.getSession("Call-ID: gone").has_value()) << "precondition: the call is over";
	rig.sent.clear();

	rig.handler.handle(makePrack("gone", "ct1", "1 1 INVITE", 4, "z"));

	EXPECT_EQ(rig.sent.size(), 0u) << transcript(rig.sent);
}

// Guard: the state is bounded, inside the Session, and Session::reset clears all of it, so a recycled slot
// is not a forwarded dialog.
TEST(Forward100rel, ForwardedDialogStateIsResetWithTheSession)
{
	Session s("first", nullptr);
	EXPECT_FALSE(s.isForwardedReliable());
	EXPECT_FALSE(s.matchesForwardedProvisional(1, 5));

	s.openForwardedReliable(5);
	EXPECT_TRUE(s.isForwardedReliable());
	EXPECT_EQ(s.nextForwardedRSeq(), 1u);
	EXPECT_EQ(s.nextForwardedRSeq(), 0u) << "none until the first is acknowledged";
	EXPECT_TRUE(s.matchesForwardedProvisional(1, 5));
	EXPECT_FALSE(s.matchesForwardedProvisional(1, 6));
	EXPECT_FALSE(s.matchesForwardedProvisional(2, 5));
	s.acknowledgeForwardedProvisional();
	EXPECT_FALSE(s.matchesForwardedProvisional(1, 5));
	EXPECT_EQ(s.nextForwardedRSeq(), 2u);

	s.reset("second", nullptr);
	EXPECT_FALSE(s.isForwardedReliable());
	EXPECT_FALSE(s.matchesForwardedProvisional(2, 5));
	EXPECT_FALSE(s.matchesForwardedProvisional(0, 0));
	s.openForwardedReliable(9);
	EXPECT_EQ(s.nextForwardedRSeq(), 1u) << "a recycled slot starts its RSeq again";
	EXPECT_FALSE(s.isEchoDialog()) << "the echo state is a separate one";
}

// ── Every other route keeps the 420 it has on main ────────────────────────────

namespace
{
	// An INVITE with Require: 100rel, flag on, is refused 420 naming 100rel, nothing is forked or relayed
	// to any phone, and the wire is the same as with the flag off.
	void expectRefused(const std::function<void(Rig&)>& setup, const std::string& to, const std::string& id)
	{
		SCOPED_TRACE("to " + to);
		std::string off, on;
		for (const bool flag : {false, true})
		{
			Rig rig(flag);
			setup(rig);
			rig.sent.clear();
			rig.handler.handle(makeInvite("500", to, kCallerIp, id, kRequire));
			EXPECT_FALSE(firstTo(rig.sent, kCallerIp, "SIP/2.0 420 Bad Extension", "Unsupported: 100rel").empty())
				<< (flag ? "flag on\n" : "flag off\n") << transcript(rig.sent);
			EXPECT_EQ(countOutsideTheCaller(rig.sent), 0u) << "no phone is rung";
			(flag ? on : off) = transcript(rig.sent);
		}
		EXPECT_EQ(off, on);
	}
}

TEST(Forward100rel, RingAllAndHuntGroupsStayAt420)
{
	// A phone registered under the group's own number is still the group: onInvite tests the group first.
	auto setup = [](Rig& rig) {
		rig.handler.handle(makeRegister("601", "192.168.7.71"));
		rig.handler.handle(makeRegister("602", "192.168.7.72"));
		rig.handler.setRingGroup("601", "600,610", "ringall");
		rig.handler.setRingGroup("602", "600,610", "hunt");
	};
	expectRefused(setup, "601", "grp-all");
	expectRefused(setup, "602", "grp-hunt");
}

TEST(Forward100rel, PagingStaysAt420)
{
	auto setup = [](Rig& rig) {
		rig.handler.handle(makeRegister("980", "192.168.7.73"));
		rig.handler.setPageZone("980", "600,610");
	};
	expectRefused(setup, "999", "page-all");
	expectRefused(setup, "980", "page-zone");
}

TEST(Forward100rel, CallForwardingStaysAt420)
{
	for (const char* trigger : {"always", "busy", "noanswer"})
	{
		SCOPED_TRACE(trigger);
		expectRefused([trigger](Rig& rig) { rig.handler.setForward("600", trigger, "610"); }, "600",
			std::string("cf-") + trigger);
	}
}

TEST(Forward100rel, DialRulesStayAt420)
{
	{
		SCOPED_TRACE("a rule that matches a registered extension");
		expectRefused([](Rig& rig) {
			rig.handler.setRingGroup("601", "600,610", "ringall");
			rig.handler.setDialRule("600", "group", "601");
		}, "600", "rule-ext");
	}
	{
		SCOPED_TRACE("an outside-line rule");
		expectRefused([](Rig& rig) { rig.handler.setDialRule("9XXXXXXXXXX", "trunk", "1", 1); },
			"92025550123", "rule-trunk");
	}
}

TEST(Forward100rel, SpecialExtensionsStayAt420)
{
	// 440 tone, 888 conference, 997 multicast page, 555 anchor, 796 voicemail, 700 park orbit, *8 and **600
	// pickup. The REGISTER guard refuses the reserved ones, but a phone can register as a park orbit or a
	// pickup code, and onInvite dispatches on those before it looks for the phone.
	for (const char* ext : {"440", "888", "997", "555", "796", "700", "*8", "**600"})
	{
		expectRefused([](Rig& rig) {
			rig.handler.handle(makeRegister("700", "192.168.7.74"));
			rig.handler.handle(makeRegister("*8", "192.168.7.75"));
		}, ext, std::string("sp-") + ext);
	}
}

TEST(Forward100rel, ACalleeThatIsNotRegisteredStaysAt420)
{
	expectRefused([](Rig&) {}, "699", "unreg");
}

// onInvite refuses these two with 403 (#497) or by dispatch; on main the header gate answers first, and still does.
TEST(Forward100rel, ACallerThatIsNotRegisteredFromItsOwnAddressStaysAt420)
{
	struct Row
	{
		const char* what;
		std::string from;
		std::string ip;
	};
	const std::vector<Row> rows = {
		{"a registered caller from another address", "500", "192.168.7.99"},
		{"a caller that is not registered",          "123", "192.168.7.98"},
	};
	int n = 0;
	for (const Row& row : rows)
	{
		SCOPED_TRACE(row.what);
		std::string off, on;
		for (const bool flag : {false, true})
		{
			Rig rig(flag);
			rig.handler.handle(makeInvite(row.from, "600", row.ip, "who" + std::to_string(n), kRequire));
			EXPECT_FALSE(firstTo(rig.sent, row.ip, "SIP/2.0 420 Bad Extension", "Unsupported: 100rel").empty())
				<< (flag ? "flag on\n" : "flag off\n") << transcript(rig.sent);
			EXPECT_EQ(countTo(rig.sent, kCalleeIp, ""), 0u);
			(flag ? on : off) = transcript(rig.sent);
		}
		EXPECT_EQ(off, on);
		++n;
	}
}

TEST(Forward100rel, ACallFromTheTrunkSbcStaysAt420)
{
	for (const bool flag : {false, true})
	{
		SCOPED_TRACE(flag ? "flag on" : "flag off");
		Rig rig(flag);
		const std::string tapi = std::string("test_fwd100rel_tapi_") + (flag ? "on" : "off") + ".cfg";
		const std::string did = std::string("test_fwd100rel_did_") + (flag ? "on" : "off") + ".cfg";
		std::remove(tapi.c_str());
		std::remove(did.c_str());
		rig.handler.setTelephonyStorePathsForTest(tapi, did);
		SipTrunk::Config c;
		std::snprintf(c.host, sizeof(c.host), "%s", kSbcIp);
		c.port = 5060;
		std::snprintf(c.fromUser, sizeof(c.fromUser), "%s", "15551230000");
		c.enabled = true;
		rig.handler.setTrunkConfig(c);
		rig.sent.clear();

		rig.handler.handle(makeInvite("+12025550177", "600", kSbcIp, "carrier", kRequire));

		EXPECT_FALSE(firstTo(rig.sent, kSbcIp, "SIP/2.0 420 Bad Extension", "Unsupported: 100rel").empty())
			<< transcript(rig.sent);
		EXPECT_EQ(countTo(rig.sent, kCalleeIp, ""), 0u) << "the extension is not rung";

		// A phone registered from the SBC's own address (an FXS port on the carrier's gateway) is a
		// registered caller, and onInvite takes its call as an ordinary one. It is still not a call this
		// change accepts: the SBC's address is excluded as a source.
		rig.handler.handle(makeRegister("620", kSbcIp));
		rig.sent.clear();
		rig.handler.handle(makeInvite("620", "600", kSbcIp, "fxs", kRequire));
		EXPECT_FALSE(firstTo(rig.sent, kSbcIp, "SIP/2.0 420 Bad Extension", "Unsupported: 100rel").empty())
			<< transcript(rig.sent);
		EXPECT_EQ(countTo(rig.sent, kCalleeIp, ""), 0u);
		std::remove(tapi.c_str());
		std::remove(did.c_str());
	}
}

// ── Rule 5: emergency traffic is never changed ────────────────────────────────

namespace
{
	std::string runPsapCallback(bool flag)
	{
		Rig rig(flag);
		const Call call = startCall(rig, "psap", "Require: 100rel\r\nPriority: psap-callback\r\n");
		EXPECT_FALSE(call.relayed.empty()) << transcript(rig.sent);
		EXPECT_TRUE(hasToken(call.relayed, {"require"}, "100rel"))
			<< "a PSAP callback is forwarded exactly as it was: its Require is not stripped";
		EXPECT_EQ(rig.handler.getEmergencyHeaderYields(), 1u) << "it takes the header gate's emergency yield";
		EXPECT_FALSE(anySent(rig.sent, "420 Bad Extension"));
		rig.calleeAnswers(call.relayed, "180 Ringing", "ct1");
		const std::string ringing = firstTo(rig.sent, kCallerIp, "SIP/2.0 180 Ringing");
		EXPECT_FALSE(ringing.empty());
		EXPECT_EQ(headerValue(ringing, "rseq"), "") << "its 180 is the callee's own, unreliable";
		EXPECT_FALSE(hasToken(ringing, {"require"}, "100rel"));
		rig.sent.clear();
		rig.handler.handle(makePrack("psap", "ct1", "1 1 INVITE"));
		EXPECT_EQ(rig.sent.size(), 0u) << "a PRACK on its dialog stays unanswered, as on main";
		rig.calleeAnswers(call.relayed, "200 OK", "ct1");
		return transcript(rig.sent);
	}
}

// Guard, passes on main and must keep passing: isEmergencyTraffic() covers a PSAP callback on any To, and
// that is the one emergency INVITE that does reach the forward path. Flag off and on are the same.
TEST(Forward100rel, PsapCallbackToAnExtensionIsForwardedUnchangedWithTheFlagOffAndOn)
{
	const std::string off = runPsapCallback(false);
	const std::string on = runPsapCallback(true);
	EXPECT_EQ(off, on);
}

// Guard, passes on main: 911 and 933 never reach the forward path. Flag off and on are the same wire, with
// no 420 and no RSeq, and each takes the header gate's emergency yield.
TEST(Forward100rel, Emergency911And933AreTheSameWithTheFlagOffAndOn)
{
	for (const char* number : {"911", "933"})
	{
		SCOPED_TRACE(number);
		std::string off, on;
		for (const bool flag : {false, true})
		{
			Rig rig(flag);
			rig.handler.handle(makeInvite("500", number, kCallerIp, std::string("em-") + number, kRequire));
			EXPECT_FALSE(anySent(rig.sent, "420 Bad Extension"));
			EXPECT_FALSE(anySent(rig.sent, "RSeq:"));
			EXPECT_EQ(rig.handler.getEmergencyHeaderYields(), 1u);
			(flag ? on : off) = transcript(rig.sent);
		}
		EXPECT_EQ(off, on);
	}
}

// ── Via reality, and the heap ─────────────────────────────────────────────────

// Red on main (the 420). The PBX pushes no Via of its own on relayed requests, so a callee that follows RFC 3261 §18.2.2 to
// the letter answers the caller itself and the PBX never sees its 180. The call must still complete: no
// provisional of the PBX's, no PRACK owed, the 200 relayed (it is rebuilt here, with the PBX's Contact), and
// both sides torn down once.
TEST(Forward100rel, ACallWhoseProvisionalTheCalleeSendsToTheCallerDirectlyStillCompletes)
{
	Rig rig(true);
	const Call call = startCall(rig, "direct", kRequire);
	ASSERT_FALSE(call.relayed.empty());
	rig.sent.clear();

	rig.calleeAnswers(call.relayed, "200 OK", "ct1");

	const std::string ok = firstTo(rig.sent, kCallerIp, "SIP/2.0 200 OK", "CSeq: 1 INVITE");
	ASSERT_FALSE(ok.empty()) << transcript(rig.sent);
	EXPECT_EQ(headerValue(ok, "rseq"), "");
	EXPECT_NE(headerValue(ok, "contact").find(kPbx), std::string::npos);
	rig.handler.handle(makeInDialog("ACK", "direct", "ct1", 1));
	EXPECT_FALSE(firstTo(rig.sent, kCalleeIp, "ACK ").empty()) << "the ACK reaches the callee";
	rig.handler.handle(makeInDialog("BYE", "direct", "ct1", 2));
	const std::string bye = firstTo(rig.sent, kCalleeIp, "BYE ");
	ASSERT_FALSE(bye.empty());
	rig.calleeAnswers(bye, "200 OK", "ct1");
	EXPECT_FALSE(rig.handler.getSession("Call-ID: direct").has_value()) << "the call is torn down";
}

namespace
{
	constexpr int kPairs = 8;
	std::string pairCaller(int k) { return std::to_string(520 + k); }
	std::string pairCallee(int k) { return std::to_string(540 + k); }
	std::string pairCallerIp(int k) { return "192.168.8." + std::to_string(20 + k); }
	std::string pairCalleeIp(int k) { return "192.168.8." + std::to_string(40 + k); }

	// Gives every slot of the process-wide message pool more and longer header lines than any message below,
	// so which slot a message lands in never shows up as a slot's first-use allocation in a measurement.
	void warmMessagePool()
	{
		std::string raw = "OPTIONS sip:warm@server SIP/2.0\r\n";
		for (int i = 0; i < 24; ++i) raw += "X-Warm-" + std::to_string(i) + ": " + std::string(160, 'w') + "\r\n";
		raw += "Content-Length: 0\r\n\r\n";
		std::vector<std::shared_ptr<SipMessage>> held;
		for (int i = 0; i < POCKETDIAL_MSG_POOL; ++i)
		{
			if (auto m = RequestsHandler::getMessageFromPool(raw, addrFor("192.168.8.250"))) held.push_back(std::move(m));
		}
	}

	// Fresh registrations queue register beeps; decline them as a busy phone does, so the beep table is empty.
	void declineBeeps(Rig& rig)
	{
		rig.sent.clear();
		rig.handler.fireRegisterBeepsForTest();
		for (const auto& [addr, msg] : Sent(rig.sent))
		{
			const std::string raw = rawOf(msg);
			if (raw.rfind("INVITE ", 0) != 0) continue;
			const std::string busy =
				"SIP/2.0 486 Busy Here\r\n"
				"Via: " + headerValue(raw, "via") + "\r\n"
				"From: " + headerValue(raw, "from") + "\r\n"
				"To: " + headerValue(raw, "to") + ";tag=busy486\r\n"
				"Call-ID: " + headerValue(raw, "call-id") + "\r\n"
				"CSeq: " + headerValue(raw, "cseq") + "\r\n"
				"Content-Length: 0\r\n\r\n";
			rig.handler.handle(RequestsHandler::getMessageFromPool(busy, addr));
		}
	}

	void settle(Rig& rig)
	{
		rig.handler.sweepTransactionsForTest(std::chrono::steady_clock::now() + std::chrono::minutes(5));
		rig.handler.forceNextTickForTest();
		rig.handler.tick();
		rig.sent.clear();
	}

	// One whole call: INVITE, 180, (PRACK,) 200, ACK, BYE. Returns false if any step did not happen.
	bool wholeCall(Rig& rig, int i, bool require100rel)
	{
		const int k = i % kPairs;
		const std::string id = "heap-" + std::to_string(i) + "-5c0a9e7d41b2f6a3";
		rig.handler.handle(makeInvite(pairCaller(k), pairCallee(k), pairCallerIp(k), id, require100rel ? kRequire : ""));
		const std::string relayed = firstTo(rig.sent, pairCalleeIp(k), "INVITE ");
		if (relayed.empty()) return false;
		rig.calleeAnswers(relayed, "180 Ringing", "ct1", "", false, pairCalleeIp(k), pairCallee(k));
		const std::string ringing = firstTo(rig.sent, pairCallerIp(k), "SIP/2.0 180 Ringing");
		if (ringing.empty() || (headerValue(ringing, "rseq") == "1") != require100rel) return false;
		if (require100rel)
		{
			rig.handler.handle(makePrack(id, "ct1", "1 1 INVITE", 2, "p", pairCallerIp(k), pairCaller(k), pairCallee(k)));
			if (firstTo(rig.sent, pairCallerIp(k), "SIP/2.0 200 OK", "CSeq: 2 PRACK").empty()) return false;
		}
		rig.calleeAnswers(relayed, "200 OK", "ct1", "", false, pairCalleeIp(k), pairCallee(k));
		rig.handler.handle(makeInDialog("ACK", id, "ct1", 1, pairCallerIp(k), pairCaller(k), pairCallee(k)));
		rig.sent.clear();
		rig.handler.handle(makeInDialog("BYE", id, "ct1", 3, pairCallerIp(k), pairCaller(k), pairCallee(k)));
		const std::string bye = firstTo(rig.sent, pairCalleeIp(k), "BYE ");
		if (bye.empty()) return false;
		rig.calleeAnswers(bye, "200 OK", "ct1", "", false, pairCalleeIp(k), pairCallee(k));
		return !rig.handler.getSession("Call-ID: " + id).has_value();
	}

	// Live heap blocks after each measured call that differ from the baseline after warm-up ("" when none).
	std::string heapDrift(bool require100rel, int& failed, std::size_t& bytesGrowth)
	{
		Rig rig(true);
		warmMessagePool();
		for (int k = 0; k < kPairs; ++k)
		{
			rig.handler.handle(makeRegister(pairCaller(k), pairCallerIp(k)));
			rig.handler.handle(makeRegister(pairCallee(k), pairCalleeIp(k), ";line=1"));
		}
		declineBeeps(rig);
		for (int i = 0; i < POCKETDIAL_CDR_RECORDS; ++i) rig.handler.recordCallForTest(pairCaller(i % kPairs), "888");
		settle(rig);
		settle(rig);

		constexpr int kWarmup = 2 * kPairs;
		constexpr int kMeasured = 2 * kPairs;
		failed = 0;
		for (int i = 0; i < kWarmup; ++i)
		{
			if (!wholeCall(rig, i, require100rel)) ++failed;
			settle(rig);
		}
		const std::size_t blocks0 = heapLiveBlocks();
		const std::size_t bytes0 = heapLiveBytes();
		std::string drift;
		std::size_t bytes = bytes0;
		for (int i = kWarmup; i < kWarmup + kMeasured; ++i)
		{
			if (!wholeCall(rig, i, require100rel)) ++failed;
			settle(rig);
			// Fewer blocks than the baseline is a pooled message's parked line buffer being released or
			// reused, not a call keeping something: only a call that ends above the baseline leaks.
			if (heapLiveBlocks() > blocks0)
			{
				drift += " " + std::to_string(i - kWarmup + 1) + ": +" +
					std::to_string(heapLiveBlocks() - blocks0) + " blocks;";
			}
			bytes = heapLiveBytes();
		}
		bytesGrowth = bytes > bytes0 ? bytes - bytes0 : 0;
		return drift;
	}
}

// Guard (#284): the takeover keeps nothing per call. Its state is four Session fields; the header lines the 180
// gains are the pooled message's own, so after warm-up the live heap blocks must not drift from call to call.
// The same loop without Require: 100rel is the control. What a takeover call allocates while it runs (the two
// header lines and the Contact it rewrites, as the 777 echo's 180 does) it frees again.
TEST(Forward100rel, ReliableForwardedCallsReturnTheHeapToBaseline)
{
	if (!heapLiveTracked()) GTEST_SKIP() << "this C library cannot report block sizes";
	int failedControl = 0, failed = 0;
	std::size_t growthControl = 0, growth = 0;
	const std::string control = heapDrift(false, failedControl, growthControl);
	const std::string drift = heapDrift(true, failed, growth);

	EXPECT_EQ(failedControl, 0) << "a plain forwarded call did not complete; the control proves nothing";
	EXPECT_EQ(failed, 0) << "a reliable forwarded call did not complete; the heap figures prove nothing";
	EXPECT_EQ(control, "") << "the control (no Require: 100rel) drifts, so the figure below is not the takeover's";
	EXPECT_EQ(drift, "");
	EXPECT_LE(growth, std::size_t{512});
}

namespace
{
	// Heap allocations the PBX makes while it handles the callee's 180, on the fourth call of a kind (pool and
	// outbox capacity warm), with the message already built and the capture sized.
	std::size_t allocsOfCalleeRinging(bool require100rel)
	{
		Rig rig(true);
		warmMessagePool();
		rig.sent.reserve(256);
		std::size_t n = 0;
		for (int i = 0; i < 4; ++i)
		{
			const std::string id = "alloc-" + std::to_string(i);
			const Call call = startCall(rig, id, require100rel ? kRequire : "");
			const auto ringing = Rig::calleeMessage(call.relayed, "180 Ringing", "ct1");
			{
				AllocGuard guard;
				rig.handler.handle(ringing);
				n = guard.delta();
			}
			if (require100rel) rig.handler.handle(makePrack(id, "ct1", "1 1 INVITE"));
			rig.calleeAnswers(call.relayed, "200 OK", "ct1");
			rig.handler.handle(makeInDialog("ACK", id, "ct1", 1));
			rig.sent.clear();
			rig.handler.handle(makeInDialog("BYE", id, "ct1", 3));
			rig.calleeAnswers(firstTo(rig.sent, kCalleeIp, "BYE "), "200 OK", "ct1");
			settle(rig);
		}
		return n;
	}
}

// Guard (#284): a reliable 180 costs no heap beyond what relaying the plain one costs.
TEST(Forward100rel, TheReliable180AllocatesNoMoreThanThePlainOne)
{
	const std::size_t plain = allocsOfCalleeRinging(false);
	const std::size_t reliable = allocsOfCalleeRinging(true);
	EXPECT_EQ(reliable, plain) << "operator new calls while handling the callee's 180: plain " << plain
		<< ", reliable " << reliable;
}
