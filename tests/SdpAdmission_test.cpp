// SdpAdmission_test.cpp — SipMessage::checkSdp() and the SDP admission gate in
// RequestsHandler::handle() (docs/THREAT_MODEL.md T-7).
//
// The lesson these pin: SDP's a= extension grammar looks like a line-oriented
// key/value format and is actually a nested dispatcher. The UNISOC T612 VoLTE
// RCE (SSD advisory, 2026; CWE-674) was a normal MMTel video offer whose body
// carried `a=acap:1 acap:1 acap:1 ...`; the modem's acap decoder recursed once
// per token until the task stack overflowed into a neighbour. pocket-dial's
// defence is not "our parser happens not to recurse" — it is:
//
//   * every SDP body is structurally capped (bytes, lines, line length, tokens
//     per line, formats per m= line) in one flat, allocation-free pass BEFORE
//     any decoder sees it, and a violation refuses the whole body;
//   * the RFC 5939 / 6871 / 7104 capability-negotiation attributes are refused
//     outright, because this PBX does not implement them and must not relay
//     them to a phone that might;
//   * the gate runs in handle() for every SDP-bearing message — initial INVITE,
//     re-INVITE, UPDATE, ACK, and every response — so a well-formed SIP start
//     line buys the body no trust at all;
//   * the decoders that do run (codec policy, direction, SipSdpMessage) touch
//     no heap and hold no function pointers on the parser task's stack.
//
// Recursion itself is pinned by tests/tools/check_parser_callgraph.py, which
// compiles the SIP sources with GCC's -fcallgraph-info and fails on any cycle.

#include <gtest/gtest.h>

#include <atomic>
#include <cstdlib>
#include <new>
#include <string>
#include <utility>
#include <vector>

#include "RequestsHandler.hpp"
#include "SipMessage.hpp"
#include "SipSdpMessage.hpp"

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#else
#include <arpa/inet.h>
#endif

// ── Process-wide allocation counter ─────────────────────────────────────────
// Replaces the global operator new for this test binary so a test can assert
// that a decode path performed ZERO heap allocations. Counting is the only
// change — memory still comes from malloc/free, so every other test in the
// binary behaves exactly as before.
namespace
{
	std::atomic<size_t> g_allocs{0};
}
void* operator new(std::size_t n)
{
	g_allocs.fetch_add(1, std::memory_order_relaxed);
	if (void* p = std::malloc(n ? n : 1)) return p;
	throw std::bad_alloc();
}
void* operator new[](std::size_t n) { return operator new(n); }
void operator delete(void* p) noexcept { std::free(p); }
void operator delete(void* p, std::size_t) noexcept { std::free(p); }
void operator delete[](void* p) noexcept { std::free(p); }
void operator delete[](void* p, std::size_t) noexcept { std::free(p); }

namespace
{
	using Sent = std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>>;

	sockaddr_in addrFor(const std::string& ip)
	{
		sockaddr_in s{};
		s.sin_family = AF_INET;
		s.sin_addr.s_addr = inet_addr(ip.c_str());
		s.sin_port = htons(5060);
		return s;
	}

	const std::string kCallerIp = "192.168.7.50";
	const std::string kCalleeIp = "192.168.7.60";

	const std::string kSessionLines =
		"v=0\r\n"
		"o=- 0 0 IN IP4 192.168.7.50\r\n"
		"s=-\r\n"
		"c=IN IP4 192.168.7.50\r\n"
		"t=0 0\r\n";

	const std::string kPcmuAudio =
		"m=audio 10000 RTP/AVP 0 8 101\r\n"
		"a=rtpmap:0 PCMU/8000\r\n"
		"a=rtpmap:8 PCMA/8000\r\n"
		"a=rtpmap:101 telephone-event/8000\r\n"
		"a=fmtp:101 0-16\r\n"
		"a=sendrecv\r\n";

	// The exact shape from the advisory: one a= line, many acap tokens.
	std::string acapFloodLine(int tokens)
	{
		std::string line = "a=acap:1";
		for (int i = 0; i < tokens; ++i) line += " acap:1";
		return line + "\r\n";
	}

	// "A normal MMTel video offer with a poison body": audio + H.264 video, the
	// kind of INVITE a VoLTE core sends all day, with `poison` appended.
	std::string mmtelVideoOffer(const std::string& poison)
	{
		return kSessionLines + kPcmuAudio +
			"m=video 10002 RTP/AVP 96\r\n"
			"a=rtpmap:96 H264/90000\r\n"
			"a=fmtp:96 profile-level-id=42e01e;packetization-mode=1\r\n"
			"a=sendrecv\r\n" + poison;
	}

	// A codec-rich softphone offer with ICE/DTLS trimmings — the busiest body a
	// legitimate endpoint on this LAN will ever send. Must pass untouched.
	std::string richOffer()
	{
		return kSessionLines +
			"m=audio 10000 RTP/AVP 9 0 8 18 96 97 101\r\n"
			"a=rtpmap:9 G722/8000\r\n"
			"a=rtpmap:0 PCMU/8000\r\n"
			"a=rtpmap:8 PCMA/8000\r\n"
			"a=rtpmap:18 G729/8000\r\n"
			"a=fmtp:18 annexb=no\r\n"
			"a=rtpmap:96 opus/48000/2\r\n"
			"a=fmtp:96 minptime=10;useinbandfec=1;stereo=0;sprop-stereo=0;maxplaybackrate=48000\r\n"
			"a=rtpmap:97 iLBC/8000\r\n"
			"a=fmtp:97 mode=30\r\n"
			"a=rtpmap:101 telephone-event/8000\r\n"
			"a=fmtp:101 0-16\r\n"
			"a=ptime:20\r\n"
			"a=maxptime:150\r\n"
			"a=rtcp:10001 IN IP4 192.168.7.50\r\n"
			"a=rtcp-mux\r\n"
			"a=rtcp-fb:* nack\r\n"
			"a=ice-ufrag:F7gI\r\n"
			"a=ice-pwd:x9cml/YzichV2+XlhiMu8g\r\n"
			"a=candidate:1 1 UDP 2130706431 192.168.7.50 10000 typ host\r\n"
			"a=candidate:2 1 UDP 1694498815 203.0.113.9 41234 typ srflx raddr 192.168.7.50 rport 10000\r\n"
			"a=fingerprint:sha-256 19:E2:1C:3B:4B:9F:81:E6:B8:5C:F4:A5:A8:D8:73:04:BB:05:2F:70:9F:04:A9:0E:05:E9:26:33:E8:70:88:A2\r\n"
			"a=setup:actpass\r\n"
			"a=mid:audio\r\n"
			"a=ssrc:1234567890 cname:user@host\r\n"
			"a=X-nat:0\r\n"
			"a=sendrecv\r\n";
	}

	std::string inviteRaw(const std::string& body, const std::string& callId = "sdp-adm",
	                      int cseq = 1, const std::string& contentType = "application/sdp",
	                      const std::string& toLine = "To: <sip:600@server>")
	{
		return
			"INVITE sip:600@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + kCallerIp + ":5060;branch=z9hG4bK" + callId + std::to_string(cseq) + "\r\n"
			"From: <sip:500@server>;tag=ft" + callId + "\r\n" +
			toLine + "\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: " + std::to_string(cseq) + " INVITE\r\n"
			"Max-Forwards: 70\r\n"
			"Contact: <sip:500@" + kCallerIp + ":5060>\r\n"
			"Content-Type: " + contentType + "\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
	}

	SipMessage make(const std::string& body)
	{
		return SipMessage(inviteRaw(body), addrFor(kCallerIp));
	}

	std::shared_ptr<SipMessage> makeRegister(const std::string& ext, const std::string& srcIp)
	{
		std::string raw =
			"REGISTER sip:server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + srcIp + ":5060;branch=z9hG4bKr" + ext + "\r\n"
			"From: <sip:" + ext + "@server>;tag=rt" + ext + "\r\n"
			"To: <sip:" + ext + "@server>\r\n"
			"Call-ID: reg-" + ext + "\r\n"
			"CSeq: 1 REGISTER\r\n"
			"Contact: <sip:" + ext + "@" + srcIp + ":5060>;expires=3600\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addrFor(srcIp));
	}

	std::string extractHeaderLine(const std::string& raw, const std::string& name)
	{
		size_t pos = 0;
		while (pos < raw.size())
		{
			size_t eol = raw.find("\r\n", pos);
			if (eol == std::string::npos) eol = raw.size();
			std::string line = raw.substr(pos, eol - pos);
			if (line.size() > name.size() && line.compare(0, name.size(), name) == 0) return line;
			pos = eol + 2;
		}
		return {};
	}

	std::string findSentTo(const Sent& sent, const sockaddr_in& addr, const std::string& needle)
	{
		for (auto it = sent.rbegin(); it != sent.rend(); ++it)
		{
			if (it->first.sin_addr.s_addr != addr.sin_addr.s_addr) continue;
			if (!it->second) continue;
			std::string raw = it->second->toString();
			if (raw.find(needle) != std::string::npos) return raw;
		}
		return {};
	}

	bool anySentContains(const Sent& sent, const std::string& needle)
	{
		for (const auto& [addr, msg] : sent)
			if (msg && msg->toString().find(needle) != std::string::npos) return true;
		return false;
	}

	struct Harness
	{
		Sent sent;
		RequestsHandler handler;
		const sockaddr_in caller = addrFor(kCallerIp);
		const sockaddr_in callee = addrFor(kCalleeIp);
		Harness() : handler("192.168.7.1", 5060,
			[this](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
				sent.emplace_back(addr, std::move(msg));
			})
		{
			handler.handle(makeRegister("500", kCallerIp));
			handler.handle(makeRegister("600", kCalleeIp));
			sent.clear();
		}

		// 500 calls 600 with a plain PCMU offer; 600 answers. Returns the To
		// header (with the callee's tag) the caller must echo on any re-INVITE.
		std::string establishCall(const std::string& callId)
		{
			handler.handle(RequestsHandler::getMessageFromPool(
				inviteRaw(kSessionLines + kPcmuAudio, callId), caller));
			const std::string fork = findSentTo(sent, callee, "INVITE sip:600@");
			EXPECT_FALSE(fork.empty()) << "INVITE must be forked to 600";
			if (fork.empty()) return {};
			answer(callId, fork, kSessionLines + kPcmuAudio);
			const std::string callerOk = findSentTo(sent, caller, "SIP/2.0 200 OK");
			EXPECT_FALSE(callerOk.empty()) << "caller must receive the 200 OK";
			return extractHeaderLine(callerOk, "To:");
		}

		// 600 answers the forked INVITE with `body`.
		void answer(const std::string& callId, const std::string& fork, const std::string& body)
		{
			std::string raw =
				"SIP/2.0 200 OK\r\n" +
				extractHeaderLine(fork, "Via:") + "\r\n" +
				extractHeaderLine(fork, "From:") + "\r\n"
				"To: <sip:600@server>;tag=ans600\r\n"
				"Call-ID: " + callId + "\r\n"
				"CSeq: 1 INVITE\r\n"
				"Contact: <sip:600@" + kCalleeIp + ":5060>\r\n"
				"Content-Type: application/sdp\r\n"
				"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
			handler.handle(RequestsHandler::getMessageFromPool(raw, callee));
		}
	};
}

// ── SipMessage::checkSdp() ──────────────────────────────────────────────────

TEST(SdpAdmission, CodecRichOfferWithIceAndDtlsPasses)
{
	EXPECT_EQ(make(richOffer()).checkSdp(), SipMessage::SdpVerdict::Ok);
	EXPECT_EQ(make(kSessionLines + kPcmuAudio).checkSdp(), SipMessage::SdpVerdict::Ok);
	EXPECT_EQ(make(mmtelVideoOffer("")).checkSdp(), SipMessage::SdpVerdict::Ok);
}

TEST(SdpAdmission, T612AcapFloodIsRefusedAsCapabilityNegotiation)
{
	// The literal attack: many acap tokens on one line, after a normal
	// audio+video offer. Refused by NAME before any token is counted or decoded.
	EXPECT_EQ(make(mmtelVideoOffer(acapFloodLine(200))).checkSdp(),
	          SipMessage::SdpVerdict::CapabilityNegotiation);

	// Spread one acap per line instead: the first one is enough.
	std::string perLine;
	for (int i = 0; i < 200; ++i) perLine += "a=acap:1\r\n";
	EXPECT_EQ(make(mmtelVideoOffer(perLine)).checkSdp(),
	          SipMessage::SdpVerdict::CapabilityNegotiation);

	// And a single, perfectly innocuous-looking one: still refused. This PBX
	// does not do RFC 5939, so there is nothing to "handle gracefully".
	EXPECT_EQ(make(mmtelVideoOffer("a=acap:1 a=rtpmap:0 PCMU/8000\r\n")).checkSdp(),
	          SipMessage::SdpVerdict::CapabilityNegotiation);
}

TEST(SdpAdmission, EveryCapNegAttributeIsRefusedAndCsupIsNot)
{
	static const char* kRefused[] = {
		"acap", "tcap", "pcfg", "acfg", "creq",              // RFC 5939
		"rmcap", "omcap", "mfcap", "mscap", "lcfg", "sescap", // RFC 6871
		"bcap", "ccap", "icap",                              // RFC 7104
		"ACAP", "Pcfg",                                      // names are case-insensitive
	};
	for (const char* name : kRefused)
	{
		const std::string body = kSessionLines + kPcmuAudio + "a=" + name + ":1\r\n";
		EXPECT_EQ(make(body).checkSdp(), SipMessage::SdpVerdict::CapabilityNegotiation)
			<< "a=" << name << " must be refused";
	}
	// a=csup only advertises support; an offer carrying it alone is still a
	// plain RFC 3264 offer (RFC 5939 §3.3.2) and must not be refused.
	EXPECT_EQ(make(kSessionLines + kPcmuAudio + "a=csup:med-v0\r\n").checkSdp(),
	          SipMessage::SdpVerdict::Ok);
}

TEST(SdpAdmission, StructuralCapsAreHardErrors)
{
	using V = SipMessage::SdpVerdict;

	// Line length.
	EXPECT_EQ(make(kSessionLines + kPcmuAudio + "a=fmtp:96 " + std::string(SdpLimits::kMaxLineBytes, 'x') + "\r\n").checkSdp(),
	          V::LineTooLong);
	EXPECT_EQ(make(kSessionLines + kPcmuAudio + "a=fmtp:96 " + std::string(SdpLimits::kMaxLineBytes - 10, 'x') + "\r\n").checkSdp(),
	          V::Ok) << "exactly at the cap is fine";

	// Line count.
	std::string manyLines = kSessionLines + kPcmuAudio;
	for (unsigned i = 0; i < SdpLimits::kMaxLines; ++i) manyLines += "a=ptime:20\r\n";
	EXPECT_EQ(make(manyLines).checkSdp(), V::TooManyLines);

	// Formats on an m= line.
	std::string wideM = "m=audio 10000 RTP/AVP";
	for (unsigned i = 0; i <= SdpLimits::kMaxMediaFormats; ++i) wideM += " " + std::to_string(96 + (i % 31));
	EXPECT_EQ(make(kSessionLines + wideM + "\r\n").checkSdp(), V::TooManyMediaFormats);

	// Tokens on any other line.
	std::string wideA = "a=candidate:1 1 UDP 1 192.168.7.50 10000 typ host";
	for (unsigned i = 0; i < SdpLimits::kMaxTokensPerLine; ++i) wideA += " tok";
	EXPECT_EQ(make(kSessionLines + kPcmuAudio + wideA + "\r\n").checkSdp(), V::TooManyTokens);

	// Not <type>=<value>.
	EXPECT_EQ(make(kSessionLines + "junk\r\n" + kPcmuAudio).checkSdp(), V::MalformedLine);
	EXPECT_EQ(make(kSessionLines + "=x\r\n" + kPcmuAudio).checkSdp(), V::MalformedLine);
	EXPECT_EQ(make(kSessionLines + "1=x\r\n" + kPcmuAudio).checkSdp(), V::MalformedLine);
	EXPECT_EQ(make(kSessionLines + "m\r\n" + kPcmuAudio).checkSdp(), V::MalformedLine);

	// Attribute names: empty, over-long, or not a token.
	EXPECT_EQ(make(kSessionLines + kPcmuAudio + "a=:1\r\n").checkSdp(), V::BadAttributeName);
	EXPECT_EQ(make(kSessionLines + kPcmuAudio + "a=\r\n").checkSdp(), V::BadAttributeName);
	EXPECT_EQ(make(kSessionLines + kPcmuAudio + "a=" + std::string(SdpLimits::kMaxAttrNameBytes + 1, 'n') + ":1\r\n").checkSdp(),
	          V::BadAttributeName);
	EXPECT_EQ(make(kSessionLines + kPcmuAudio + "a=rtp map:0 PCMU/8000\r\n").checkSdp(), V::BadAttributeName);
	EXPECT_EQ(make(kSessionLines + kPcmuAudio + "a=rtpmap=0\r\n").checkSdp(), V::BadAttributeName);

	// Whole-body size, checked before anything else.
	std::string huge;
	while (huge.size() <= SdpLimits::kMaxBodyBytes) huge += "a=ptime:20\r\n";
	EXPECT_EQ(make(huge).checkSdp(), V::BodyTooLarge);
}

TEST(SdpAdmission, BareLfAndBlankLinesAreToleratedLikeTheDecodersDo)
{
	const std::string lf =
		"v=0\no=- 0 0 IN IP4 192.168.7.50\ns=-\nc=IN IP4 192.168.7.50\nt=0 0\n"
		"m=audio 10000 RTP/AVP 0\na=rtpmap:0 PCMU/8000\n\n";
	EXPECT_EQ(make(lf).checkSdp(), SipMessage::SdpVerdict::Ok);
	EXPECT_EQ(make(kSessionLines + kPcmuAudio + "\r\n").checkSdp(), SipMessage::SdpVerdict::Ok);
	EXPECT_EQ(make("").checkSdp(), SipMessage::SdpVerdict::Ok) << "empty body: nothing to refuse";
}

TEST(SdpAdmission, ContentTypeIsMatchedCaseInsensitively)
{
	// MIME types are case-insensitive; a phone would parse "Application/SDP" as
	// SDP, so the gate must see it as SDP too or it could be sidestepped.
	SipMessage upper(inviteRaw(kPcmuAudio, "ct", 1, "Application/SDP"), addrFor(kCallerIp));
	EXPECT_TRUE(upper.hasSdp());
	SipMessage lower(inviteRaw(kPcmuAudio, "ct", 1, "application/sdp"), addrFor(kCallerIp));
	EXPECT_TRUE(lower.hasSdp());
	SipMessage none(inviteRaw(kPcmuAudio, "ct", 1, "text/plain"), addrFor(kCallerIp));
	EXPECT_FALSE(none.hasSdp());
}

TEST(SdpAdmission, DecodePathsAllocateNothing)
{
	// The admission check and every SDP decoder that runs on the wire path must
	// be zero-heap: their work is bounded by SdpLimits, never by what the peer
	// chose to put in the body. Construct everything first, then count.
	SipMessage msg = make(richOffer());
	SipSdpMessage sdp(inviteRaw(richOffer()), addrFor(kCallerIp));
	std::string reinviteHold = kSessionLines + "m=audio 10000 RTP/AVP 0\r\na=sendonly\r\n";
	SipMessage hold = make(reinviteHold);

	g_allocs.store(0, std::memory_order_relaxed);
	const auto verdict = msg.checkSdp();
	const bool audio = msg.offersSupportedAudio(/*allowWideband=*/true);
	const auto dir = hold.getSdpDirection();
	const int port = sdp.getRtpPort();
	const auto conn = sdp.getConnectionInformation();
	const size_t allocs = g_allocs.load(std::memory_order_relaxed);

	EXPECT_EQ(verdict, SipMessage::SdpVerdict::Ok);
	EXPECT_TRUE(audio);
	EXPECT_EQ(dir, SipMessage::SdpDirection::SendOnly);
	EXPECT_EQ(port, 10000);
	EXPECT_EQ(conn, "c=IN IP4 192.168.7.50");
	EXPECT_EQ(allocs, 0u) << "checkSdp/offersSupportedAudio/getSdpDirection/SipSdpMessage must not touch the heap";
}

TEST(SdpAdmission, CodecPolicyStillMatchesTheOldDecoderOnRealOffers)
{
	// The heap-free rewrite of applyAudioPolicy must be behaviourally identical
	// to the map/vector version it replaced (tests/SdpNegotiate_test.cpp covers
	// the policy itself; this pins the edge the rewrite changed the most).
	SipMessage m = make(richOffer());
	ASSERT_TRUE(m.filterAudioCodecs(/*allowWideband=*/true));
	const std::string body(m.getBody());
	EXPECT_NE(body.find("m=audio 10000 RTP/AVP 9 0 8 101\r\n"), std::string::npos) << body;
	EXPECT_EQ(body.find("a=rtpmap:18 "), std::string::npos) << "dropped codec's rtpmap must go";
	EXPECT_EQ(body.find("a=fmtp:96 "), std::string::npos) << "dropped codec's fmtp must go";
	EXPECT_NE(body.find("a=fmtp:101 0-16\r\n"), std::string::npos) << "kept codec's fmtp must stay";
	EXPECT_NE(body.find("a=candidate:2 "), std::string::npos) << "unrelated attributes are relayed";

	// A telephone-event rtpmap whose name is upper-case still counts as the event.
	SipMessage ev = make(kSessionLines + "m=audio 10000 RTP/AVP 101\r\na=rtpmap:101 TELEPHONE-EVENT/8000\r\n");
	EXPECT_FALSE(ev.offersSupportedAudio(true)) << "telephone-event alone is not audio";
}

// ── The gate in RequestsHandler::handle() ───────────────────────────────────

TEST(SdpAdmissionGate, InviteWithAcapFloodGets488WithReasonAndIsNotForked)
{
	Harness h;
	h.handler.handle(RequestsHandler::getMessageFromPool(
		inviteRaw(mmtelVideoOffer(acapFloodLine(200)), "t612"), h.caller));

	const std::string rsp = findSentTo(h.sent, h.caller, "SIP/2.0 488 Not Acceptable Here");
	ASSERT_FALSE(rsp.empty()) << "the poison INVITE must be answered 488";
	EXPECT_NE(rsp.find("Warning: 399 192.168.7.1 \"SDP refused: capability negotiation (RFC 5939) not supported\""),
	          std::string::npos) << rsp;
	EXPECT_EQ(rsp.find("acap"), std::string::npos) << "the 488 must not echo the body";
	EXPECT_FALSE(anySentContains(h.sent, "INVITE sip:600@")) << "must not reach the callee";
	EXPECT_FALSE(h.handler.getSession("Call-ID: t612").has_value()) << "refused before any session";
	EXPECT_EQ(h.handler.getSdpRejected(), 1u);
}

TEST(SdpAdmissionGate, InviteOverStructuralLimitsGets488)
{
	Harness h;
	std::string wideM = "m=audio 10000 RTP/AVP";
	for (unsigned i = 0; i <= SdpLimits::kMaxMediaFormats; ++i) wideM += " " + std::to_string(96 + (i % 31));
	h.handler.handle(RequestsHandler::getMessageFromPool(
		inviteRaw(kSessionLines + wideM + "\r\n", "wide"), h.caller));

	const std::string rsp = findSentTo(h.sent, h.caller, "SIP/2.0 488 Not Acceptable Here");
	ASSERT_FALSE(rsp.empty());
	EXPECT_NE(rsp.find("\"SDP refused: too many media formats\""), std::string::npos) << rsp;
	EXPECT_FALSE(anySentContains(h.sent, "INVITE sip:600@"));
	EXPECT_EQ(h.handler.getSdpRejected(), 1u);
}

TEST(SdpAdmissionGate, LegitimateRichOfferIsStillForwarded)
{
	Harness h;
	h.handler.handle(RequestsHandler::getMessageFromPool(inviteRaw(richOffer(), "rich"), h.caller));

	EXPECT_FALSE(anySentContains(h.sent, "488 Not Acceptable Here"));
	const std::string fork = findSentTo(h.sent, h.callee, "INVITE sip:600@");
	ASSERT_FALSE(fork.empty()) << "a busy-but-legitimate offer must be forked";
	EXPECT_NE(fork.find("a=fingerprint:sha-256"), std::string::npos) << "unrelated attributes relayed intact";
	EXPECT_EQ(h.handler.getSdpRejected(), 0u);
}

TEST(SdpAdmissionGate, PoisonReinviteIsRefusedNotRelayedToTheHeldPeer)
{
	// Mid-dialog bodies are relayed UNTOUCHED to the peer phone (hold/resume),
	// which is exactly how a PBX becomes the delivery vector for a body that
	// would exploit the phone. The gate runs before onReinvite ever sees it.
	Harness h;
	const std::string callId = "reinv";
	const std::string dialogTo = h.establishCall(callId);
	ASSERT_NE(dialogTo.find("tag="), std::string::npos);
	auto session = h.handler.getSession("Call-ID: " + callId);
	ASSERT_TRUE(session.has_value());
	ASSERT_EQ(session.value()->getState(), Session::State::Connected);
	h.sent.clear();

	// "Hold" re-INVITE whose SDP is the T612 body.
	const std::string poison = mmtelVideoOffer(acapFloodLine(200));
	h.handler.handle(RequestsHandler::getMessageFromPool(
		inviteRaw(poison, callId, 2, "application/sdp", dialogTo), h.caller));

	const std::string rsp = findSentTo(h.sent, h.caller, "SIP/2.0 488 Not Acceptable Here");
	ASSERT_FALSE(rsp.empty()) << "the poison re-INVITE must be answered 488";
	EXPECT_TRUE(findSentTo(h.sent, h.callee, "acap").empty()) << "nothing of it may reach 600";
	EXPECT_TRUE(findSentTo(h.sent, h.callee, "INVITE").empty()) << "no re-INVITE relayed to 600";
	EXPECT_EQ(session.value()->getState(), Session::State::Connected) << "hold state must not flip";
	EXPECT_EQ(h.handler.getSdpRejected(), 1u);
}

TEST(SdpAdmissionGate, PoisonAnswerIsDroppedNotRelayedToTheCaller)
{
	// A response cannot be answered 488; it is dropped, and the INVITE
	// transaction it would have "accepted" is left exactly as it was.
	Harness h;
	const std::string callId = "ans";
	h.handler.handle(RequestsHandler::getMessageFromPool(
		inviteRaw(kSessionLines + kPcmuAudio, callId), h.caller));
	const std::string fork = findSentTo(h.sent, h.callee, "INVITE sip:600@");
	ASSERT_FALSE(fork.empty());
	auto session = h.handler.getSession("Call-ID: " + callId);
	ASSERT_TRUE(session.has_value());
	const auto before = session.value()->getState();
	h.sent.clear();

	h.answer(callId, fork, mmtelVideoOffer(acapFloodLine(200)));

	EXPECT_TRUE(findSentTo(h.sent, h.caller, "SIP/2.0 200 OK").empty()) << "poison answer must not be relayed";
	EXPECT_TRUE(findSentTo(h.sent, h.caller, "acap").empty());
	EXPECT_EQ(session.value()->getState(), before) << "a dropped answer must not connect the call";
	EXPECT_EQ(h.handler.getSdpRejected(), 1u);
}

TEST(SdpAdmissionGate, UpperCaseContentTypeCannotSidestepTheGate)
{
	Harness h;
	h.handler.handle(RequestsHandler::getMessageFromPool(
		inviteRaw(mmtelVideoOffer(acapFloodLine(200)), "case", 1, "Application/SDP"), h.caller));

	EXPECT_FALSE(findSentTo(h.sent, h.caller, "SIP/2.0 488 Not Acceptable Here").empty());
	EXPECT_FALSE(anySentContains(h.sent, "INVITE sip:600@"));
	EXPECT_EQ(h.handler.getSdpRejected(), 1u);
}

// ── Issue #196: RFC 3264 offer/answer through the real handler path ─────────

namespace
{
	// An INVITE from 500 to a service extension the board answers itself.
	std::string serviceInviteRaw(const std::string& dest, const std::string& body, const std::string& callId)
	{
		return
			"INVITE sip:" + dest + "@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + kCallerIp + ":5060;branch=z9hG4bK" + callId + "\r\n"
			"From: <sip:500@server>;tag=ft" + callId + "\r\n"
			"To: <sip:" + dest + "@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Max-Forwards: 70\r\n"
			"Contact: <sip:500@" + kCallerIp + ":5060>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
	}
}

TEST(SdpOfferAnswerGate, BoardAnswersEveryOfferedStreamInOrderRejectingVideoWithPortZero)
{
	// The old builder answered a PCMU-only single m= to whatever was offered, so
	// a phone offering audio+video had its VIDEO port matched against our audio
	// line (issue #196, RFC audit row 8866). RFC 3264 §6: one m= per offered m=,
	// same order; the stream we cannot take is answered with port 0.
	Harness h;
	h.handler.handle(RequestsHandler::getMessageFromPool(
		serviceInviteRaw("440", mmtelVideoOffer(""), "oa-440"), h.caller));

	const std::string ok = findSentTo(h.sent, h.caller, "SIP/2.0 200 OK");
	ASSERT_FALSE(ok.empty()) << "440 must answer";
	const std::string body = ok.substr(ok.find("\r\n\r\n") + 4);

	const size_t audio = body.find("m=audio ");
	const size_t video = body.find("m=video 0 RTP/AVP 96\r\n");
	ASSERT_NE(audio, std::string::npos) << body;
	ASSERT_NE(video, std::string::npos) << "video must be present and rejected, not omitted: " << body;
	EXPECT_LT(audio, video) << "offer order: audio first, video second";
	EXPECT_EQ(body.find("m=audio ", audio + 1), std::string::npos) << "exactly one audio m=";

	// Formats: the offer's list (0 8 101) intersected with what the board
	// terminates (PCMU), in the offer's order, plus the offered DTMF PT with
	// the OFFERED fmtp range, not our own.
	EXPECT_NE(body.find(" RTP/AVP 0 101\r\n"), std::string::npos) << body;
	EXPECT_NE(body.find("a=rtpmap:101 telephone-event/8000\r\n"), std::string::npos) << body;
	EXPECT_NE(body.find("a=fmtp:101 0-16\r\n"), std::string::npos) << body;
	EXPECT_EQ(body.find("PCMA"), std::string::npos) << "PCMA is not something the board terminates: " << body;
	EXPECT_NE(body.find("a=sendonly\r\n"), std::string::npos) << "440 is a one-way tone: " << body;

	// Content-Length still equals the body bytes (the 777-bug class).
	const std::string cl = extractHeaderLine(ok, "Content-Length:");
	EXPECT_EQ(std::stoul(cl.substr(cl.find(':') + 1)), body.size());
}

TEST(SdpOfferAnswerGate, RelayedAnswerListingAnUnofferedCodecIsDroppedNotRelayed)
{
	// Issue #196 item 5: the caller's INVITE was gated, the callee's 200 OK was
	// not. A 200 OK whose m= names a payload type the offer never contained is
	// not an answer to that offer (RFC 3264 §6.1) and must not reach the caller.
	Harness h;
	const std::string callId = "oa-bad-answer";
	h.handler.handle(RequestsHandler::getMessageFromPool(
		inviteRaw(kSessionLines + kPcmuAudio, callId), h.caller));
	const std::string fork = findSentTo(h.sent, h.callee, "INVITE sip:600@");
	ASSERT_FALSE(fork.empty());
	auto session = h.handler.getSession("Call-ID: " + callId);
	ASSERT_TRUE(session.has_value());
	const auto before = session.value()->getState();
	h.sent.clear();

	// G.729 was never offered.
	h.answer(callId, fork, kSessionLines + "m=audio 20000 RTP/AVP 18\r\na=rtpmap:18 G729/8000\r\n");

	EXPECT_TRUE(findSentTo(h.sent, h.caller, "SIP/2.0 200 OK").empty()) << "invalid answer must not be relayed";
	EXPECT_EQ(session.value()->getState(), before) << "a dropped answer must not connect the call";

	// The callee's corrected retransmit is judged afresh and goes through.
	h.answer(callId, fork, kSessionLines + "m=audio 20000 RTP/AVP 0 101\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:101 telephone-event/8000\r\n");
	EXPECT_FALSE(findSentTo(h.sent, h.caller, "SIP/2.0 200 OK").empty()) << "a valid answer still relays";
	EXPECT_EQ(session.value()->getState(), Session::State::Connected);
}

TEST(SdpOfferAnswerGate, RelayedAnswerThatDropsAnOfferedStreamIsDropped)
{
	// RFC 3264 §6: the answer MUST contain exactly one m= per offered m=. An
	// answer to an audio+video offer that omits the video line (instead of
	// rejecting it with port 0) is malformed and is not relayed.
	Harness h;
	const std::string callId = "oa-fewer-m";
	h.handler.handle(RequestsHandler::getMessageFromPool(
		inviteRaw(mmtelVideoOffer(""), callId), h.caller));
	const std::string fork = findSentTo(h.sent, h.callee, "INVITE sip:600@");
	ASSERT_FALSE(fork.empty());
	h.sent.clear();

	h.answer(callId, fork, kSessionLines + kPcmuAudio);   // audio only: one m= short
	EXPECT_TRUE(findSentTo(h.sent, h.caller, "SIP/2.0 200 OK").empty()) << "one m= short of the offer";

	h.answer(callId, fork, kSessionLines + kPcmuAudio + "m=video 0 RTP/AVP 96\r\n");   // rejected properly
	EXPECT_FALSE(findSentTo(h.sent, h.caller, "SIP/2.0 200 OK").empty()) << "port-0 rejection is a valid answer";
}
