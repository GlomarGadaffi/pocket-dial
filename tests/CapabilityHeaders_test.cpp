// CapabilityHeaders_test.cpp — issue #199 root cause 2, the half that OPTIONS
// alone does not cover.
//
// Commit 464dc01 (#200) built addCapabilityHeaders() and wired it into exactly
// one place: the 200 OK to an OPTIONS request. That makes the PBX's
// capabilities *discoverable by asking*, which is worth having — but it is not
// what actually gates the three features #199 names. A conformant phone reads
// `Allow:` off the messages of the dialog it is in, and most phones never send
// an OPTIONS at all:
//
//   RFC 3311 §5.1 — a UAC MUST NOT send UPDATE unless UPDATE is in the target's
//                   Allow. Without it, onUpdate() is dead code.
//   RFC 3891 §4   — a phone will not offer a Replaces-based pickup without
//                   `Supported: replaces`.
//
// So this file pins the advertisement on the two paths that reach every phone:
// the registrar's 200 OK (seen by every handset, every lease period, before it
// ever places a call) and the 2xx the PBX builds when it is itself the UAS.
//
// It also pins the two ways this could do HARM, which matter more than the
// advertisement itself:
//
//   1. Never on a RELAYED message. For an ordinary extension-to-extension call
//      this engine is a forwarding proxy / forked-UAC hybrid, not a B2BUA:
//      callee B's 200 OK reaches caller A carrying B's OWN Allow/Supported.
//      Writing this PBX's list over B's would tell A that B accepts UPDATE on
//      the strength of the PBX supporting it — a claim about the far end the
//      PBX is in no position to make.
//   2. Never twice. Responses are built by CLONING the request, and
//      getMessageFromPool(const SipMessage&) copies every header line, so a
//      phone that put `Allow:` in its own request has already put an Allow line
//      in our response before we reach it. addHeader() appends unconditionally;
//      setHeaderOnce() replaces.
//
// Everything here goes through handle() end to end, because the gap #199 found
// survived precisely BECAUSE the only existing assertion was on a hand-built
// OPTIONS exchange.

#include <gtest/gtest.h>

#include <string>
#include <utility>
#include <vector>

#include "ConferenceRoom.hpp"
#include "RequestsHandler.hpp"

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#else
#include <arpa/inet.h>
#endif

namespace
{
	constexpr const char* kServerIp = "192.168.41.1";

	sockaddr_in addrFor(const std::string& ip, uint16_t port = 5060)
	{
		sockaddr_in a{};
		a.sin_family = AF_INET;
		a.sin_addr.s_addr = inet_addr(ip.c_str());
		a.sin_port = htons(port);
		return a;
	}

	using Outbox = std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>>;

	std::string sdpBody(const std::string& ip, int port = 10000)
	{
		return
			"v=0\r\n"
			"o=- 0 0 IN IP4 " + ip + "\r\n"
			"s=-\r\n"
			"c=IN IP4 " + ip + "\r\n"
			"t=0 0\r\n"
			"m=audio " + std::to_string(port) + " RTP/AVP 0\r\n"
			"a=rtpmap:0 PCMU/8000\r\n";
	}

	// `extraHeaders` lets a test send a REGISTER that already carries its own
	// Allow/Supported, which is the duplicate-header case.
	std::shared_ptr<SipMessage> makeRegister(const std::string& ext, const std::string& ip,
		const std::string& callId, const std::string& extraHeaders = "")
	{
		std::string raw =
			"REGISTER sip:server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + ip + ":5060;branch=z9hG4bKr" + callId + "\r\n"
			"From: <sip:" + ext + "@server>;tag=rt" + callId + "\r\n"
			"To: <sip:" + ext + "@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 REGISTER\r\n"
			"Contact: <sip:" + ext + "@" + ip + ":5060>;expires=3600\r\n" +
			extraHeaders +
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addrFor(ip));
	}

	std::shared_ptr<SipMessage> makeInvite(const std::string& from, const std::string& to,
		const std::string& ip, const std::string& callId, int cseq = 1,
		const std::string& extraHeaders = "")
	{
		std::string body = sdpBody(ip);
		std::string raw =
			"INVITE sip:" + to + "@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + ip + ":5060;branch=z9hG4bKi" + callId +
				std::to_string(cseq) + "\r\n"
			"From: <sip:" + from + "@server>;tag=ct" + callId + "\r\n"
			"To: <sip:" + to + "@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: " + std::to_string(cseq) + " INVITE\r\n"
			"Max-Forwards: 70\r\n"
			"Contact: <sip:" + from + "@" + ip + ":5060>\r\n" +
			extraHeaders +
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		return RequestsHandler::getMessageFromPool(raw, addrFor(ip));
	}

	// Count how many header lines in `raw` have exactly this name.
	int headerCount(const std::string& raw, const std::string& name)
	{
		int n = 0;
		size_t pos = 0;
		while (pos < raw.size())
		{
			size_t eol = raw.find("\r\n", pos);
			if (eol == std::string::npos) eol = raw.size();
			if (eol == pos) break;   // blank line: end of the header block
			if (raw.compare(pos, name.size(), name) == 0 &&
				pos + name.size() < raw.size() && raw[pos + name.size()] == ':')
			{
				++n;
			}
			pos = eol + 2;
		}
		return n;
	}

	std::string headerValue(const std::string& raw, const std::string& name)
	{
		size_t pos = 0;
		while (pos < raw.size())
		{
			size_t eol = raw.find("\r\n", pos);
			if (eol == std::string::npos) eol = raw.size();
			if (eol == pos) break;
			if (raw.compare(pos, name.size(), name) == 0 &&
				pos + name.size() < raw.size() && raw[pos + name.size()] == ':')
			{
				size_t v = pos + name.size() + 1;
				while (v < eol && (raw[v] == ' ' || raw[v] == '\t')) ++v;
				return raw.substr(v, eol - v);
			}
			pos = eol + 2;
		}
		return {};
	}

	// The first outbound message whose start line contains `needle`.
	std::string firstWithStartLine(const Outbox& sent, const std::string& needle)
	{
		for (const auto& [addr, msg] : sent)
		{
			(void)addr;
			std::string raw = msg ? msg->toString() : std::string{};
			if (raw.rfind(needle, 0) == 0) return raw;
		}
		return {};
	}
}

// ── The registrar's 200 OK: the one message every phone sees ─────────────────

TEST(CapabilityHeaders, RegisterOkAdvertisesWhatThisPbxActuallyHandles)
{
	// OPTIONS only tells a phone that bothers to ask, and plenty never do. The
	// REGISTER 200 OK reaches every handset on every lease period, before it
	// ever places a call — so a phone that has not learned `Supported: replaces`
	// here will not offer BLF-key pickup at all.
	Outbox sent;
	RequestsHandler handler(kServerIp, 5060,
		[&sent](const sockaddr_in& a, std::shared_ptr<SipMessage> m) {
			sent.emplace_back(a, std::move(m));
		});

	handler.handle(makeRegister("410", "192.168.41.10", "reg-410"));

	const std::string ok = firstWithStartLine(sent, "SIP/2.0 200 OK");
	ASSERT_FALSE(ok.empty()) << "the REGISTER was not answered 200 OK at all";

	const std::string allow = headerValue(ok, "Allow");
	ASSERT_FALSE(allow.empty()) << "no Allow header on the registrar's 200 OK";
	// The two that #199 names as gated on this advertisement.
	EXPECT_NE(allow.find("UPDATE"), std::string::npos)
		<< "RFC 3311 §5.1: without this a compliant phone never sends UPDATE";
	EXPECT_NE(allow.find("INVITE"), std::string::npos);
	EXPECT_NE(allow.find("REFER"), std::string::npos);

	EXPECT_NE(headerValue(ok, "Supported").find("replaces"), std::string::npos)
		<< "RFC 3891 §4: without this a phone will not offer a Replaces pickup";
	EXPECT_NE(headerValue(ok, "Accept").find("application/sdp"), std::string::npos);
	EXPECT_EQ(headerValue(ok, "Allow-Events"), "dialog");
}

TEST(CapabilityHeaders, TimerIsStillNotClaimedOnTheRegistrarPath)
{
	// A guard, not a feature. #200 deliberately left `timer` out because RFC 4028
	// §9 makes Min-SE processing and the 422 response mandatory for an entity
	// that advertises the extension, and neither exists (getMinSESecs() still has
	// no caller). The PBX only ever reaps an expiry, never refreshes — so
	// claiming the tag would promise a session nobody is responsible for keeping
	// alive. Advertising it on the registrar path would be the same lie in a new
	// place. See the checklist on #198 for what would have to land first.
	Outbox sent;
	RequestsHandler handler(kServerIp, 5060,
		[&sent](const sockaddr_in& a, std::shared_ptr<SipMessage> m) {
			sent.emplace_back(a, std::move(m));
		});

	handler.handle(makeRegister("411", "192.168.41.11", "reg-411"));
	const std::string ok = firstWithStartLine(sent, "SIP/2.0 200 OK");
	ASSERT_FALSE(ok.empty());

	const std::string supported = headerValue(ok, "Supported");
	EXPECT_EQ(supported.find("timer"), std::string::npos)
		<< "Supported: " << supported << " — RFC 4028 support here is passive "
		   "(no Min-SE, no 422, no refresh), so the tag would be an over-claim";
	EXPECT_EQ(supported.find("100rel"), std::string::npos)
		<< "100rel needs PRACK, which has no handler";
	// Under-claiming is the safe direction, so the method list must not grow
	// entries the handler table cannot actually dispatch.
	const std::string allow = headerValue(ok, "Allow");
	EXPECT_EQ(allow.find("PRACK"), std::string::npos);
	EXPECT_EQ(allow.find("PUBLISH"), std::string::npos);
	EXPECT_EQ(allow.find("NOTIFY"), std::string::npos)
		<< "the PBX SENDS NOTIFYs; nothing here accepts one";
}

TEST(CapabilityHeaders, APhonesOwnAllowDoesNotSurviveIntoOurAnswer)
{
	// Responses are built by cloning the request, so the phone's own Allow line
	// is already in our 200 OK before addCapabilityHeaders() runs. addHeader()
	// would append a second one, and the result on the wire reads as a single
	// merged capability set belonging to nobody — a phone could conclude the PBX
	// supports PRACK because IT does.
	Outbox sent;
	RequestsHandler handler(kServerIp, 5060,
		[&sent](const sockaddr_in& a, std::shared_ptr<SipMessage> m) {
			sent.emplace_back(a, std::move(m));
		});

	handler.handle(makeRegister("412", "192.168.41.12", "reg-412",
		"Allow: INVITE, ACK, BYE, CANCEL, PRACK, PUBLISH\r\n"
		"Supported: 100rel, timer, gruu\r\n"));

	const std::string ok = firstWithStartLine(sent, "SIP/2.0 200 OK");
	ASSERT_FALSE(ok.empty());

	EXPECT_EQ(headerCount(ok, "Allow"), 1)
		<< "exactly one Allow line, ours:\n" << ok;
	EXPECT_EQ(headerCount(ok, "Supported"), 1)
		<< "exactly one Supported line, ours:\n" << ok;

	// And it must be OUR list that survived, not the phone's.
	EXPECT_EQ(headerValue(ok, "Allow").find("PRACK"), std::string::npos)
		<< "the phone's PRACK claim was echoed back as though it were ours";
	EXPECT_EQ(headerValue(ok, "Supported").find("timer"), std::string::npos)
		<< "the phone's timer claim was echoed back as though it were ours";
	EXPECT_NE(headerValue(ok, "Allow").find("UPDATE"), std::string::npos);
}

// ── A 2xx the PBX builds as the real UAS ────────────────────────────────────

TEST(CapabilityHeaders, AnAuthoredInviteAnswerCarriesAllowSoUpdateIsReachable)
{
	// The 888 conference leg is one the PBX itself terminates, so it is genuinely
	// the UAS of the dialog this 2xx opens and these headers describe it. RFC
	// 3261 §13.3.1 / §20.5: a 2xx to an INVITE SHOULD carry Allow — and it is the
	// only place a phone looks to decide whether it may send UPDATE *in this
	// dialog*, which is exactly what RFC 3311 §5.1 gates on.
	Outbox sent;
	RequestsHandler handler(kServerIp, 5060,
		[&sent](const sockaddr_in& a, std::shared_ptr<SipMessage> m) {
			sent.emplace_back(a, std::move(m));
		});

	const std::string ext(ConferenceRoom::EXT);
	handler.handle(makeRegister("413", "192.168.41.13", "reg-413"));
	sent.clear();
	handler.handle(makeInvite("413", ext, "192.168.41.13", "conf-cap"));

	const std::string ok = firstWithStartLine(sent, "SIP/2.0 200 OK");
	ASSERT_FALSE(ok.empty()) << "the conference INVITE was not answered 200 OK";

	EXPECT_NE(headerValue(ok, "Allow").find("UPDATE"), std::string::npos)
		<< "an authored 2xx must advertise UPDATE, or onUpdate stays dead code";
	EXPECT_NE(headerValue(ok, "Supported").find("replaces"), std::string::npos);
	EXPECT_EQ(headerCount(ok, "Allow"), 1);

	// The body must still be intact: addCapabilityHeaders() runs inside
	// buildOkWithSdp() before the Content-Type/Content-Length surgery, so a
	// mistake there would corrupt the SDP rather than just the headers.
	EXPECT_NE(ok.find("application/sdp"), std::string::npos);
	EXPECT_NE(ok.find("m=audio"), std::string::npos);
	const size_t sep = ok.find("\r\n\r\n");
	ASSERT_NE(sep, std::string::npos);
	EXPECT_EQ(headerValue(ok, "Content-Length"),
		std::to_string(ok.size() - (sep + 4)))
		<< "Content-Length must still match the body after the headers were added";
}

// ── The boundary: never stamp our capabilities onto someone else's message ───

TEST(CapabilityHeaders, ARelayedAnswerKeepsTheCalleesOwnCapabilities)
{
	// An ordinary extension-to-extension call. The PBX forwards callee B's 200 OK
	// to caller A; B is the real UAS on that dialog. Overwriting B's Allow with
	// the PBX's would tell A that B accepts UPDATE and understands `replaces`
	// purely because the PBX does — a claim about the far end the PBX cannot
	// make, and the same dishonesty the `timer` exclusion refuses to commit.
	Outbox sent;
	RequestsHandler handler(kServerIp, 5060,
		[&sent](const sockaddr_in& a, std::shared_ptr<SipMessage> m) {
			sent.emplace_back(a, std::move(m));
		});

	const std::string callerIp = "192.168.41.20";
	const std::string calleeIp = "192.168.41.21";
	handler.handle(makeRegister("420", callerIp, "reg-420"));
	handler.handle(makeRegister("421", calleeIp, "reg-421"));
	handler.handle(makeInvite("420", "421", callerIp, "relay-cap"));

	sent.clear();
	{
		const std::string body = sdpBody(calleeIp, 20000);
		const std::string raw =
			"SIP/2.0 200 OK\r\n"
			"Via: SIP/2.0/UDP " + callerIp + ":5060;branch=z9hG4bKirelay-cap1\r\n"
			"From: <sip:420@server>;tag=ctrelay-cap\r\n"
			"To: <sip:421@server>;tag=calleetag\r\n"
			"Call-ID: relay-cap\r\n"
			"CSeq: 1 INVITE\r\n"
			"Contact: <sip:421@" + calleeIp + ":5060>\r\n"
			"Allow: INVITE, ACK, BYE, CANCEL, PRACK\r\n"
			"Supported: 100rel\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		handler.handle(RequestsHandler::getMessageFromPool(raw, addrFor(calleeIp)));
	}

	const std::string relayed = firstWithStartLine(sent, "SIP/2.0 200 OK");
	ASSERT_FALSE(relayed.empty()) << "the callee's 200 OK never reached the caller";

	EXPECT_NE(headerValue(relayed, "Allow").find("PRACK"), std::string::npos)
		<< "the callee's own Allow must reach the caller untouched:\n" << relayed;
	EXPECT_EQ(headerValue(relayed, "Allow").find("UPDATE"), std::string::npos)
		<< "this PBX must not tell the caller that the CALLEE accepts UPDATE";
	EXPECT_EQ(headerCount(relayed, "Allow"), 1);
}

// ── The gap that would have made `Allow: UPDATE` an active regression ───────

TEST(CapabilityHeaders, AnUpdatesAnswerIsRelayedBackToTheOppositeLeg)
{
	// onUpdate() forwards an SDP-bearing UPDATE to the opposite leg and relies on
	// the peer's 200 OK coming back through onOk(). That return path used to sit
	// inside an `if (CSeq contains INVITE)` gate, so a `CSeq: n UPDATE` response
	// matched nothing, fell past the Bye check at the bottom of onOk(), and was
	// silently dropped — the sender's UPDATE transaction then timed out.
	//
	// That was survivable only while nothing told phones this PBX accepts UPDATE.
	// Advertising `Allow: UPDATE` without fixing it would have turned a dormant
	// gap into an active regression on exactly the well-behaved phones the header
	// is meant to serve, which is why the two land together.
	Outbox sent;
	RequestsHandler handler(kServerIp, 5060,
		[&sent](const sockaddr_in& a, std::shared_ptr<SipMessage> m) {
			sent.emplace_back(a, std::move(m));
		});

	const std::string callerIp = "192.168.41.30";
	const std::string calleeIp = "192.168.41.31";
	handler.handle(makeRegister("430", callerIp, "reg-430"));
	handler.handle(makeRegister("431", calleeIp, "reg-431"));
	handler.handle(makeInvite("430", "431", callerIp, "upd-cap"));
	{
		const std::string body = sdpBody(calleeIp, 30000);
		const std::string raw =
			"SIP/2.0 200 OK\r\n"
			"Via: SIP/2.0/UDP " + callerIp + ":5060;branch=z9hG4bKiupd-cap1\r\n"
			"From: <sip:430@server>;tag=ctupd-cap\r\n"
			"To: <sip:431@server>;tag=calleetag\r\n"
			"Call-ID: upd-cap\r\n"
			"CSeq: 1 INVITE\r\n"
			"Contact: <sip:431@" + calleeIp + ":5060>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		handler.handle(RequestsHandler::getMessageFromPool(raw, addrFor(calleeIp)));
	}

	// The caller sends an in-dialog UPDATE with a new offer; it is relayed on.
	sent.clear();
	{
		const std::string body = sdpBody(callerIp, 30002);
		const std::string raw =
			"UPDATE sip:431@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + callerIp + ":5060;branch=z9hG4bKupd2\r\n"
			"From: <sip:430@server>;tag=ctupd-cap\r\n"
			"To: <sip:431@server>;tag=calleetag\r\n"
			"Call-ID: upd-cap\r\n"
			"CSeq: 2 UPDATE\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		handler.handle(RequestsHandler::getMessageFromPool(raw, addrFor(callerIp)));
	}
	ASSERT_FALSE(firstWithStartLine(sent, "UPDATE sip:").empty())
		<< "the UPDATE was never relayed to the callee";

	// THE REGRESSION: the callee answers it, and that 200 OK must reach the
	// caller. Before the fix it went nowhere at all.
	sent.clear();
	{
		const std::string body = sdpBody(calleeIp, 30004);
		const std::string raw =
			"SIP/2.0 200 OK\r\n"
			"Via: SIP/2.0/UDP " + callerIp + ":5060;branch=z9hG4bKupd2\r\n"
			"From: <sip:430@server>;tag=ctupd-cap\r\n"
			"To: <sip:431@server>;tag=calleetag\r\n"
			"Call-ID: upd-cap\r\n"
			"CSeq: 2 UPDATE\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		handler.handle(RequestsHandler::getMessageFromPool(raw, addrFor(calleeIp)));
	}

	bool reachedCaller = false;
	for (const auto& [addr, msg] : sent)
	{
		if (!msg) continue;
		if (msg->toString().rfind("SIP/2.0 200 OK", 0) != 0) continue;
		if (addr.sin_addr.s_addr == addrFor(callerIp).sin_addr.s_addr) reachedCaller = true;
	}
	EXPECT_TRUE(reachedCaller)
		<< "the 200 OK to a relayed UPDATE must reach the leg that sent it, or "
		   "the phone's UPDATE transaction times out";
}

// ── The request-side half of the authored-vs-relayed rule ───────────────────

TEST(CapabilityHeaders, APassedThroughReinviteGetsNoPbxSideRetransmitTimer)
{
	// The request-side mirror of ARelayedAnswerKeepsTheCalleesOwnCapabilities,
	// and a subtler failure than it looks.
	//
	// onReinvite()'s hold/resume relay forwards phone A's re-INVITE to phone B by
	// pushing the SAME object onto the outbox — no clone, no Via rewrite, so it
	// still carries A's branch. A owns retransmitting that request under its own
	// client transaction (RFC 3261 §17.1.1) and keeps doing so until B's answer
	// comes back through the PBX. If the transaction layer also armed a timer on
	// it, one lost packet would put TWO copies of the same branch on the wire —
	// the exact double-send the response-side rule exists to prevent, relocated
	// to requests.
	//
	// Pointer identity is the test: a message the PBX built is never the object
	// it received. Tracking is therefore driven by the message's PROVENANCE, not
	// by its method — which is why a forked INVITE (a clone the PBX addressed to
	// a target the caller has never heard of, and which nothing else will ever
	// retransmit) still gets full coverage.
	Outbox sent;
	RequestsHandler handler(kServerIp, 5060,
		[&sent](const sockaddr_in& a, std::shared_ptr<SipMessage> m) {
			sent.emplace_back(a, std::move(m));
		});

	const std::string callerIp = "192.168.41.40";
	const std::string calleeIp = "192.168.41.41";
	handler.handle(makeRegister("440", callerIp, "reg-440"));
	handler.handle(makeRegister("441", calleeIp, "reg-441"));
	handler.handle(makeInvite("440", "441", callerIp, "hold-cap"));
	{
		const std::string body = sdpBody(calleeIp, 40000);
		const std::string raw =
			"SIP/2.0 200 OK\r\n"
			"Via: SIP/2.0/UDP " + callerIp + ":5060;branch=z9hG4bKihold-cap1\r\n"
			"From: <sip:440@server>;tag=cthold-cap\r\n"
			"To: <sip:441@server>;tag=calleetag\r\n"
			"Call-ID: hold-cap\r\n"
			"CSeq: 1 INVITE\r\n"
			"Contact: <sip:441@" + calleeIp + ":5060>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		handler.handle(RequestsHandler::getMessageFromPool(raw, addrFor(calleeIp)));
	}

	// A holds: an in-dialog re-INVITE, relayed on to B untouched.
	sent.clear();
	const size_t beforeRelay = handler.getClientTransactionCount();
	{
		std::string body = sdpBody(callerIp, 40002) + "a=sendonly\r\n";
		const std::string raw =
			"INVITE sip:441@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + callerIp + ":5060;branch=z9hG4bKhold2\r\n"
			"From: <sip:440@server>;tag=cthold-cap\r\n"
			"To: <sip:441@server>;tag=calleetag\r\n"
			"Call-ID: hold-cap\r\n"
			"CSeq: 2 INVITE\r\n"
			"Contact: <sip:440@" + callerIp + ":5060>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		handler.handle(RequestsHandler::getMessageFromPool(raw, addrFor(callerIp)));
	}

	int relayedToCallee = 0;
	for (const auto& [addr, msg] : sent)
	{
		if (!msg) continue;
		if (msg->toString().rfind("INVITE sip:", 0) != 0) continue;
		if (addr.sin_addr.s_addr == addrFor(calleeIp).sin_addr.s_addr) ++relayedToCallee;
	}
	ASSERT_EQ(relayedToCallee, 1) << "the hold re-INVITE must reach the callee exactly once";

	// Assert the DECISION, not a timer. Driving tick() in a loop would prove
	// nothing here: it self-throttles to 1 Hz, so at most one tick runs and it
	// runs microseconds after the relay — long before a 500 ms Timer A could
	// fire. Such a test passes whether or not the tracking is right. The client
	// transaction count answers the actual question.
	//
	// A DELTA, not an absolute: registering a phone fires a register-beep INVITE
	// (RegisterBeeper), which is a genuine PBX-originated request and correctly
	// holds a client slot of its own for its Timer B window. Only the change
	// across the relay is this test's business.
	EXPECT_EQ(handler.getClientTransactionCount(), beforeRelay)
		<< "the PBX armed a retransmit timer on a re-INVITE it was only relaying";
}

TEST(CapabilityHeaders, AServerOriginatedByeIsTrackedForRetransmitByTheRealEngine)
{
	// The layer-level counterpart of this lives in TransactionLayerRfc17_test.cpp
	// (FreeForCallIdStopsTheInviteButNotTheByeTearingItDown). What a layer test
	// CANNOT prove is the wiring: that a BYE the engine actually originates reaches
	// maybeTrack() through drainOutbox() and is accepted there. classify() could
	// reject it, the pass-through guard could swallow it, or the BYE could leave by
	// a path that never passes the choke point -- all invisible to FakePbxEnv.
	//
	// The register beep is the shortest real path to a server-originated BYE: a new
	// registration triggers an auto-answer INVITE, and when the phone answers,
	// RegisterBeeper ACKs and BYEs to end the call it just made.
	//
	// Scope note, deliberately stated rather than papered over: this proves the BYE
	// is TRACKED. It does not prove the retransmission fires, because tick()
	// self-throttles to 1 Hz and there is no clock injection to step it -- any test
	// claiming otherwise here would be measuring nothing. The timer schedules
	// themselves are covered at the layer, where the clock IS a parameter.
	Outbox sent;
	RequestsHandler handler(kServerIp, 5060,
		[&sent](const sockaddr_in& a, std::shared_ptr<SipMessage> m) {
			sent.emplace_back(a, std::move(m));
		});

	const std::string phoneIp = "192.168.41.50";
	handler.handle(makeRegister("450", phoneIp, "reg-450"));

	// The beep INVITE the registration just fired. Echo its dialog back so the
	// 200 OK is matched to it.
	const std::string beep = firstWithStartLine(sent, "INVITE sip:");
	ASSERT_FALSE(beep.empty()) << "the registration fired no beep INVITE";
	const std::string beepCallId = headerValue(beep, "Call-ID");
	const std::string beepVia    = headerValue(beep, "Via");
	const std::string beepFrom   = headerValue(beep, "From");
	const std::string beepTo     = headerValue(beep, "To");
	const std::string beepCSeq   = headerValue(beep, "CSeq");
	ASSERT_FALSE(beepCallId.empty());

	const size_t beforeAnswer = handler.getClientTransactionCount();
	ASSERT_GE(beforeAnswer, 1u)
		<< "the beep INVITE itself must already hold a client transaction";

	// The phone answers the beep. RegisterBeeper ACKs, then BYEs to hang it up.
	sent.clear();
	{
		const std::string raw =
			"SIP/2.0 200 OK\r\n"
			"Via: " + beepVia + "\r\n"
			"From: " + beepFrom + "\r\n"
			"To: " + beepTo + ";tag=phonetag\r\n"
			"Call-ID: " + beepCallId + "\r\n"
			"CSeq: " + beepCSeq + "\r\n"
			"Contact: <sip:450@" + phoneIp + ":5060>\r\n"
			"Content-Length: 0\r\n\r\n";
		handler.handle(RequestsHandler::getMessageFromPool(raw, addrFor(phoneIp)));
	}

	const std::string bye = firstWithStartLine(sent, "BYE sip:");
	ASSERT_FALSE(bye.empty())
		<< "answering the beep did not produce a server-originated BYE";

	// THE ASSERTION. Before this change every one of these went out exactly once
	// and was never retransmitted -- "fire and forget", in #199's words -- so a
	// single lost datagram left the handset showing a call the PBX had already
	// torn down, with nothing anywhere that would ever correct it.
	// EXACTLY one more than before, which is the only form of this assertion that
	// is not vacuous. A bare "> 0" would pass on the beep INVITE's own slot alone:
	// that slot is still occupied after the 200 OK, sitting in its RFC 6026 §8.4
	// Timer M absorb window, so it would satisfy "> 0" whether or not the BYE was
	// tracked at all.
	//
	// The exact delta also pins the other half: the ACK that went out in the same
	// pass must NOT have claimed a slot. §17.1.1.3 — an ACK is never its own
	// transaction, and putting one on a retransmit timer would emit unmatched
	// ACKs.
	const std::string ack = firstWithStartLine(sent, "ACK sip:");
	EXPECT_FALSE(ack.empty()) << "the answered beep was never ACKed";
	EXPECT_EQ(handler.getClientTransactionCount(), beforeAnswer + 1)
		<< "expected exactly one new client transaction (the BYE) and none for "
		   "the ACK sent alongside it";
}
