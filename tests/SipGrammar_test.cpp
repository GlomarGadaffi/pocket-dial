// SipGrammar_test.cpp — issue #199: the SIP/SDP wire grammar is held to the
// subset this PBX actually handles, and every bound matches a real fixed buffer.
//
// Black-box on purpose: every test drives RequestsHandler::handle() and reads
// the outbox, using only APIs that exist on main, so each one compiled and ran
// RED against the unfixed engine before the fix went in.
//
// Four things are pinned:
//   * BOUNDED   -- a field longer than the fixed buffer it is copied into is
//                  refused (400) before the copy, never silently truncated.
//   * SUBSET    -- an option tag we do not implement is 420 + Unsupported:, a
//                  body we do not parse is 415, an SDP shape we do not carry
//                  is 488. Headers peers send that we merely ignore still pass.
//   * CAPS      -- Via / Route / Record-Route / Contact entry counts, and one
//                  active audio stream per offer.
//   * EMERGENCY -- none of the above may refuse a 911/933 or urn:service:sos
//                  call. The same bytes that are refused to 600 are routed to
//                  911, and urn:service:sos is 911 (it was a 400 on main).

#include <gtest/gtest.h>

#include <cstdio>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "RequestsHandler.hpp"
#include "Sdp.hpp"
#include "SipMessage.hpp"

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#else
#include <arpa/inet.h>
#endif

namespace
{
	constexpr const char* kServerIp = "192.168.81.1";
	constexpr const char* kCallerIp = "192.168.81.50";   // ext 500
	constexpr const char* kCalleeIp = "192.168.81.60";   // ext 600
	constexpr const char* kSbcIp    = "203.0.113.5";     // RFC 5737 TEST-NET-3, never sent to

	sockaddr_in addrFor(const std::string& ip)
	{
		sockaddr_in s{};
		s.sin_family = AF_INET;
		s.sin_addr.s_addr = inet_addr(ip.c_str());
		s.sin_port = htons(5060);
		return s;
	}

	const std::string kSession =
		"v=0\r\n"
		"o=- 1 1 IN IP4 192.168.81.50\r\n"
		"s=-\r\n"
		"c=IN IP4 192.168.81.50\r\n"
		"t=0 0\r\n";

	const std::string kAudio =
		"m=audio 40000 RTP/AVP 0 101\r\n"
		"a=rtpmap:0 PCMU/8000\r\n"
		"a=rtpmap:101 telephone-event/8000\r\n"
		"a=fmtp:101 0-16\r\n"
		"a=sendrecv\r\n";

	const std::string kOffer = kSession + kAudio;

	// One INVITE, every part overridable. `extra` is inserted verbatim (CRLF
	// terminated lines) after Max-Forwards; `vias` replaces the single Via.
	struct Invite
	{
		std::string ruri        = "sip:600@server";
		std::string to          = "<sip:600@server>";
		std::string from        = "<sip:500@server>";
		std::string callId      = "sg-call";
		std::string branch;                       // default: z9hG4bK + callId
		std::string cseq        = "1 INVITE";
		std::string maxForwards = "70";
		std::string vias;                         // extra Via lines (after ours)
		std::string extra;
		std::string contentType = "application/sdp";
		std::string body        = kOffer;
		std::string method      = "INVITE";

		std::string raw() const
		{
			const std::string br = branch.empty() ? "z9hG4bK" + callId : branch;
			std::string r =
				method + " " + ruri + " SIP/2.0\r\n"
				"Via: SIP/2.0/UDP " + std::string(kCallerIp) + ":5060;branch=" + br + "\r\n" +
				vias +
				"From: " + from + ";tag=f-" + callId + "\r\n"
				"To: " + to + "\r\n"
				"Call-ID: " + callId + "\r\n"
				"CSeq: " + cseq + "\r\n"
				"Max-Forwards: " + maxForwards + "\r\n"
				"Contact: <sip:500@" + std::string(kCallerIp) + ":5060>\r\n" +
				extra;
			if (!body.empty() && !contentType.empty()) r += "Content-Type: " + contentType + "\r\n";
			r += "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
			return r;
		}
	};

	std::shared_ptr<SipMessage> makeRegister(const std::string& ext, const std::string& ip)
	{
		const std::string raw =
			"REGISTER sip:server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + ip + ":5060;branch=z9hG4bKsgr" + ext + "\r\n"
			"From: <sip:" + ext + "@server>;tag=sgr" + ext + "\r\n"
			"To: <sip:" + ext + "@server>\r\n"
			"Call-ID: sg-reg-" + ext + "\r\n"
			"CSeq: 1 REGISTER\r\n"
			"Contact: <sip:" + ext + "@" + ip + ":5060>;expires=3600\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addrFor(ip));
	}

	SipTrunk::Config trunkConfig()
	{
		SipTrunk::Config c;
		std::snprintf(c.host, sizeof(c.host), "%s", kSbcIp);
		c.port = 5060;
		std::snprintf(c.fromUser, sizeof(c.fromUser), "%s", "trunkuser");
		c.enabled = true;
		return c;
	}

	// 500 and 600 registered, and a trunk configured so a 911 has a real route:
	// "routed" is then an INVITE sip:911@<carrier>, not merely "not a 400".
	struct Bench
	{
		std::vector<std::pair<sockaddr_in, std::string>> sent;
		std::unique_ptr<RequestsHandler> handler;

		Bench()
		{
			handler = std::make_unique<RequestsHandler>(kServerIp, 5060,
				[this](const sockaddr_in& a, std::shared_ptr<SipMessage> m) {
					sent.emplace_back(a, m->toString());
				});
			handler->setTrunkConfig(trunkConfig());
			handler->handle(makeRegister("500", kCallerIp));
			handler->handle(makeRegister("600", kCalleeIp));
			sent.clear();
		}

		void send(const Invite& inv)
		{
			handler->handle(RequestsHandler::getMessageFromPool(inv.raw(), addrFor(kCallerIp)));
		}

		// Messages whose FIRST line contains `needle`, optionally to `ip` only.
		size_t count(const std::string& needle, const char* ip = nullptr) const
		{
			size_t n = 0;
			for (const auto& [addr, raw] : sent)
			{
				if (ip && addr.sin_addr.s_addr != inet_addr(ip)) continue;
				if (raw.substr(0, raw.find("\r\n")).find(needle) != std::string::npos) ++n;
			}
			return n;
		}

		// The full text of the first message to `ip` whose first line has `needle`.
		std::string find(const std::string& needle, const char* ip) const
		{
			for (const auto& [addr, raw] : sent)
			{
				if (addr.sin_addr.s_addr != inet_addr(ip)) continue;
				if (raw.substr(0, raw.find("\r\n")).find(needle) != std::string::npos) return raw;
			}
			return {};
		}

		bool forkedTo600() const { return count("INVITE sip:600@", kCalleeIp) == 1; }
		// Past the grammar and on the emergency route, which (no anchor, no trunk) refuses it.
		bool reachedEmergencyRoute() const
		{
			return count("SIP/2.0 503 Emergency Call Not Routable", kCallerIp) == 1;
		}

		// Past the grammar and placed by the anchor, which answers the INVITE synchronously.
		bool answeredByAnchor() const
		{
			return count("SIP/2.0 200", kCallerIp) == 1;
		}

		std::string dump() const
		{
			std::string out;
			for (const auto& p : sent) out += p.second.substr(0, p.second.find("\r\n")) + "\n";
			return out;
		}
	};

	// `n` extra Via lines, one entry each.
	std::string viaLines(int n)
	{
		std::string v;
		for (int i = 0; i < n; ++i)
			v += "Via: SIP/2.0/UDP 10.9.0." + std::to_string(i + 1) + ":5060;branch=z9hG4bKhop" +
				std::to_string(i) + "\r\n";
		return v;
	}

	std::string headerRepeat(const std::string& name, int n)
	{
		std::string v;
		for (int i = 0; i < n; ++i)
			v += name + ": <sip:10.9.1." + std::to_string(i + 1) + ";lr>\r\n";
		return v;
	}

	// A malformed-or-unsupported request shape and the status 600 must get.
	struct Violation
	{
		const char* what;
		const char* status;     // expected first-line prefix to the caller
		Invite      inv;
	};

	std::vector<Violation> violations()
	{
		std::vector<Violation> v;
		{ Invite i; i.callId = "sg-v-cid-" + std::string(130, 'c');
		  v.push_back({"Call-ID line over the 128-byte transaction slot", "SIP/2.0 400", i}); }
		{ Invite i; i.callId = "sg-v-br"; i.branch = "z9hG4bK" + std::string(80, 'b');
		  v.push_back({"Via branch over the 72-byte slot", "SIP/2.0 400", i}); }
		{ Invite i; i.callId = "sg-v-cseqn"; i.cseq = "99999999999 INVITE";
		  v.push_back({"CSeq number over 2^31-1", "SIP/2.0 400", i}); }
		{ Invite i; i.callId = "sg-v-cseqm"; i.cseq = "1 INVITEINVITEX";
		  v.push_back({"CSeq method over the 12-byte slot", "SIP/2.0 400", i}); }
		{ Invite i; i.callId = "sg-v-mf"; i.maxForwards = "99999";
		  v.push_back({"Max-Forwards over 255", "SIP/2.0 400", i}); }
		{ Invite i; i.callId = "sg-v-via"; i.vias = viaLines(10);
		  v.push_back({"11 Via entries", "SIP/2.0 400", i}); }
		{ Invite i; i.callId = "sg-v-rr"; i.extra = headerRepeat("Record-Route", 11);
		  v.push_back({"11 Record-Route entries", "SIP/2.0 400", i}); }
		{ Invite i; i.callId = "sg-v-route"; i.extra = headerRepeat("Route", 9);
		  v.push_back({"9 Route entries", "SIP/2.0 400", i}); }
		{ Invite i; i.callId = "sg-v-ct";
		  i.extra = "Contact: <sip:500@10.9.2.1>, <sip:500@10.9.2.2>, <sip:500@10.9.2.3>, <sip:500@10.9.2.4>\r\n";
		  v.push_back({"5 Contact entries", "SIP/2.0 400", i}); }
		{ Invite i; i.callId = "sg-v-100rel"; i.extra = "Require: 100rel\r\n";
		  v.push_back({"Require: 100rel to an ordinary extension (only the 777 echo honours it)", "SIP/2.0 420", i}); }
		{ Invite i; i.callId = "sg-v-preq"; i.extra = "Proxy-Require: sec-agree\r\n";
		  v.push_back({"Proxy-Require: sec-agree", "SIP/2.0 420", i}); }
		{ Invite i; i.callId = "sg-v-text"; i.contentType = "text/plain"; i.body = "hello\r\n";
		  v.push_back({"text/plain INVITE body", "SIP/2.0 415", i}); }
		return v;
	}
}

// ── BOUNDED / SUBSET / CAPS: each violation is refused with its own status ───

TEST(SipGrammar, EachViolationIsRefusedWithItsStatusAndNeverForwarded)
{
	for (const Violation& v : violations())
	{
		SCOPED_TRACE(v.what);
		Bench b;
		b.send(v.inv);
		EXPECT_EQ(b.count(v.status, kCallerIp), 1u) << b.dump();
		EXPECT_FALSE(b.forkedTo600()) << "refused bytes must never reach the callee:\n" << b.dump();
	}
}

TEST(SipGrammar, A420NamesTheUnsupportedTag)
{
	Bench b;
	Invite i; i.callId = "sg-420"; i.extra = "Require: timer, 100rel\r\n";
	b.send(i);
	const std::string r = b.find("SIP/2.0 420", kCallerIp);
	ASSERT_FALSE(r.empty()) << b.dump();
	EXPECT_NE(r.find("\r\nUnsupported: 100rel\r\n"), std::string::npos)
		<< "RFC 3261 §8.2.2.3: list the tag that was not understood:\n" << r;
}

TEST(SipGrammar, A415SaysWhatWeAccept)
{
	Bench b;
	Invite i; i.callId = "sg-415";
	i.contentType = "multipart/mixed;boundary=bnd";
	i.body = "--bnd\r\nContent-Type: application/sdp\r\n\r\n" + kOffer + "--bnd--\r\n";
	b.send(i);
	const std::string r = b.find("SIP/2.0 415", kCallerIp);
	ASSERT_FALSE(r.empty()) << "multipart is a 415, not a 488 from the SDP gate:\n" << b.dump();
	EXPECT_NE(r.find("\r\nAccept: application/sdp\r\n"), std::string::npos) << r;
}

TEST(SipGrammar, AtEachBufferBoundTheFieldStillFits)
{
	// Call-ID line of exactly 127 bytes ("Call-ID: " is 9) and a 71-byte branch:
	// the largest values the fixed slots hold whole. Both must be carried.
	Bench b;
	Invite i;
	i.callId = "sg-edge-" + std::string(127 - 9 - 8, 'e');
	i.branch = "z9hG4bK" + std::string(71 - 7, 'b');
	i.cseq = "2147483647 INVITE";
	i.maxForwards = "255";
	i.vias = viaLines(9);   // 10 Via entries in all
	i.extra = headerRepeat("Record-Route", 10) + headerRepeat("Route", 8);
	b.send(i);
	EXPECT_TRUE(b.forkedTo600()) << b.dump();
}

// ── SDP: one active audio stream, and the model's own caps on the wire ───────

TEST(SipGrammar, SdpShapesTheModelCannotHoldAre488)
{
	std::string twoAudio = kOffer + "m=audio 40002 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n";
	std::string fiveSections = kOffer;
	for (int i = 0; i < 4; ++i)
		fiveSections += "m=video " + std::to_string(40010 + 2 * i) + " RTP/AVP 96\r\n";
	std::string manyAttrs = kOffer;
	for (unsigned i = 0; i < sdp::Limits::kMaxAttributesPerSection; ++i) manyAttrs += "a=ptime:20\r\n";

	// sdp::parse is the oracle for the two model caps: the wire gate must agree
	// with it, or the model reads "absent" for a body the gate let through.
	sdp::Session s;
	EXPECT_EQ(sdp::parse(fiveSections, s), sdp::Verdict::TooManyMediaSections);
	EXPECT_EQ(sdp::parse(manyAttrs, s), sdp::Verdict::TooManyAttributes);

	int n = 0;
	for (const std::string& body : {twoAudio, fiveSections, manyAttrs})
	{
		SCOPED_TRACE(n);
		Bench b;
		Invite i; i.callId = "sg-sdp-" + std::to_string(n++); i.body = body;
		b.send(i);
		EXPECT_EQ(b.count("SIP/2.0 488", kCallerIp), 1u) << b.dump();
		EXPECT_FALSE(b.forkedTo600()) << b.dump();
	}
}

TEST(SipGrammar, SdpShapesWeCarryPass)
{
	const std::string video =
		"m=video 40002 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\n";
	// RFC 3264 §8: a re-offer keeps a removed stream as port 0; it is not active.
	const std::string removedAudio = kSession + "m=audio 0 RTP/AVP 0\r\n" + kAudio;
	const std::string rtcp = kOffer + "a=rtcp:40001 IN IP4 192.168.81.50\r\na=rtcp-mux\r\n";
	int n = 0;
	for (const std::string& body : {kOffer + video, removedAudio, rtcp})
	{
		SCOPED_TRACE(n);
		Bench b;
		Invite i; i.callId = "sg-sdpok-" + std::to_string(n++); i.body = body;
		b.send(i);
		EXPECT_TRUE(b.forkedTo600()) << b.dump();
	}
}

// ── Parse-and-ignore: what carriers and phones really send still passes ──────

TEST(SipGrammar, ACarrierShapedInviteWithEveryIgnoredHeaderIsCarried)
{
	Bench b;
	Invite i;
	i.callId = "sg-carrier";
	i.vias = viaLines(3);
	i.extra =
		headerRepeat("Record-Route", 4) +
		"Require: timer\r\n"
		"Supported: timer, replaces, 100rel, path\r\n"
		"Session-Expires: 1800;refresher=uac\r\n"
		"Privacy: id;header\r\n"
		"History-Info: <sip:600@server?Reason=SIP%3Bcause%3D302>;index=1\r\n"
		"Geolocation: <cid:loc@example.net>\r\n"
		"Geolocation-Routing: no\r\n"
		"P-Early-Media: supported\r\n"
		"P-Asserted-Identity: <sip:500@server>\r\n"
		"Path: <sip:10.9.3.1;lr>\r\n"
		"Diversion: <sip:700@server>;reason=unconditional\r\n"
		"Priority: urgent\r\n"
		"Reason: Q.850;cause=16\r\n"
		"Accept: application/sdp\r\n"
		"User-Agent: carrier-sbc\r\n";
	b.send(i);
	EXPECT_TRUE(b.forkedTo600()) << b.dump();
	EXPECT_EQ(b.count("SIP/2.0 4", kCallerIp), 0u) << b.dump();
}

// ── EMERGENCY: nothing above may refuse a 911 ────────────────────────────────

TEST(SipGrammar, TheBytesRefusedTo600AreRoutedTo911)
{
	for (Violation v : violations())
	{
		SCOPED_TRACE(v.what);
		{
			Bench b;
			b.send(v.inv);
			EXPECT_EQ(b.count(v.status, kCallerIp), 1u) << "to 600: refused\n" << b.dump();
		}
		{
			Bench b;
			Invite e = v.inv;
			e.ruri = "sip:911@server";
			e.to = "<sip:911@server>";
			if (e.contentType == "text/plain") { e.contentType = "application/sdp"; e.body = kOffer; }
			b.handler->setAnchorPlacesRealCallsForTest(true);
			b.send(e);
			EXPECT_TRUE(b.answeredByAnchor())
				<< "an optional header must never cost a 911 call:\n" << b.dump();
			EXPECT_EQ(b.count("SIP/2.0 4", kCallerIp), 0u) << b.dump();

			// And the caller can still hang up: an in-dialog request on the live
			// 911 carries the same Call-ID / Via / Require, and no R-URI of 911.
			// Refusing it would leave an emergency call (never reaped, #604) up.
			b.sent.clear();
			Invite bye = e;
			bye.method = "BYE";
			bye.branch = e.branch.empty() ? "z9hG4bKbye" + std::to_string(e.callId.size()) : e.branch;
			if (e.cseq == "1 INVITE") bye.cseq = "2 BYE";
			bye.body.clear();
			b.send(bye);
			EXPECT_EQ(b.count("SIP/2.0 400", kCallerIp), 0u) << "BYE on a live 911:\n" << b.dump();
			EXPECT_EQ(b.count("SIP/2.0 420", kCallerIp), 0u) << "BYE on a live 911:\n" << b.dump();
		}
	}
}

TEST(SipGrammar, UrnServiceSosIsA911Call)
{
	// RFC 5031 / 6881: a phone that knows it is dialing an emergency service
	// says so with urn:service:sos (or a sub-service) in the R-URI and To.
	for (const char* urn : {"urn:service:sos", "URN:Service:SOS", "urn:service:sos.fire"})
	{
		SCOPED_TRACE(urn);
		Bench b;
		Invite i;
		i.callId = std::string("sg-urn-") + urn;
		i.ruri = urn;
		i.to = std::string("<") + urn + ">";
		b.send(i);
		EXPECT_TRUE(b.reachedEmergencyRoute()) << "urn:service:sos must reach the carrier as 911:\n" << b.dump();
		EXPECT_EQ(b.count("SIP/2.0 400", kCallerIp), 0u) << b.dump();
	}
}

TEST(SipGrammar, APsapCallbackIsNeverRefusedForAnOptionTag)
{
	// RFC 7090: a PSAP calling back marks the INVITE Priority: psap-callback.
	// The same Require that is a 420 on an ordinary call must not be one here.
	{
		Bench b;
		Invite i; i.callId = "sg-psap-no"; i.extra = "Require: 100rel\r\n";
		b.send(i);
		EXPECT_EQ(b.count("SIP/2.0 420", kCallerIp), 1u) << b.dump();
	}
	{
		Bench b;
		Invite i; i.callId = "sg-psap-yes"; i.extra = "Priority: psap-callback\r\nRequire: 100rel\r\n";
		b.send(i);
		EXPECT_TRUE(b.forkedTo600()) << b.dump();
		EXPECT_EQ(b.count("SIP/2.0 420", kCallerIp), 0u) << b.dump();
	}
}

// #870: a dialog stores this INVITE's From and To lines, and the BYE the PBX builds
// from them has a fixed size. A line past the bound is refused with 400 at ingress.
TEST(SipGrammar, ADialogLineOverTheBoundIsRefusedAtIngress)
{
	const std::string pad(220, 'x');   // a display name: the AOR stays valid, the line grows
	for (const bool fromSide : {true, false})
	{
		SCOPED_TRACE(fromSide ? "From" : "To");
		Bench b;
		Invite i;
		if (fromSide) i.from = "\"" + pad + "\" <sip:500@server>";
		else i.to = "\"" + pad + "\" <sip:600@server>";
		b.send(i);
		EXPECT_EQ(b.count("SIP/2.0 400 From/To Line Too Long", kCallerIp), 1u) << b.dump();
		EXPECT_EQ(b.count("INVITE", kCalleeIp), 0u) << "an oversize dialog line is never routed:\n" << b.dump();
	}
}

TEST(SipGrammar, AnOrdinaryDialogLineWithinTheBoundIsStillRouted)
{
	Bench b;
	Invite i;
	i.from = "\"" + std::string(100, 'x') + "\" <sip:500@server>";
	b.send(i);
	EXPECT_EQ(b.count("SIP/2.0 400", kCallerIp), 0u) << b.dump();
	EXPECT_EQ(b.count("INVITE", kCalleeIp), 1u) << b.dump();
}

TEST(SipGrammar, AnEmergencyWithAnOversizeDialogLineIsNotRefusedForIt)
{
	// Rule 5: a 911 is never refused for its header length. It takes the emergency
	// path, which (no anchor, no trunk) answers 503 as it does for any 911 today.
	Bench b;
	Invite i;
	i.ruri = "sip:911@server";
	i.to = "<sip:911@server>";
	i.from = "\"" + std::string(220, 'x') + "\" <sip:500@server>";
	b.send(i);
	EXPECT_EQ(b.count("SIP/2.0 400", kCallerIp), 0u) << b.dump();
	EXPECT_TRUE(b.routedTo911()) << b.dump();
}
