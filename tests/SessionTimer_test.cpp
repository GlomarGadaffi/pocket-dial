// SessionTimer_test.cpp — issue #198 (RFC 4028 session timers) and the OPTIONS
// half of issue #199 (capability advertisement).
//
// #198: RequestsHandler::armSessionTimer() read Session-Expires off the CALLEE's
// 200 OK and armed an expiry reaper unconditionally, while nothing in the
// firmware has ever generated a refreshing re-INVITE or UPDATE
// (Session::getNextRefresh() still has zero consumers). sweepSessionTimers()
// then BYEs BOTH legs on expiry, so a call nobody refreshed was hung up by the
// PBX itself.
//
// Two things were wrong and both are pinned here:
//
//   1. The refresher role was inverted AND asked the wrong question. RFC 4028
//      §7.4's refresher parameter names one of the two UAs of the session —
//      "uas" the party that answered the INVITE, "uac" the party that sent it.
//      This PBX relays the caller's INVITE rather than originating one
//      (RequestsHandler.cpp:1578-1581, CallForker.cpp:22-50), so on the leg
//      armSessionTimer() runs on, the UAC is the CALLER'S PHONE and the UAS is
//      the CALLEE'S PHONE. The PBX is neither and is therefore never the
//      refresher — but the old `weRefresh = (ref == "uas")` claimed it was, in
//      exactly the case where the header designates the callee.
//
//   2. A 2xx carrying Session-Expires but NO refresher parameter violates
//      RFC 4028's UAS rules and leaves nobody responsible for refreshing. Arming then
//      guarantees a spurious BYE. This is a real shape, not a theoretical one:
//      the PBX builds responses by cloning the request, so its own 200 OK
//      echoes the caller's Session-Expires straight back with no refresher
//      attached — visible in the captured pjsip traffic in
//      tests/interop/.logs/pjsua-A.log.
//
// #199: no Allow:/Supported:/Accept: header was emitted anywhere in src/. Per
// RFC 3311 §5.1 a phone will not send UPDATE without `Allow: UPDATE`, and per
// RFC 3891 §4 it will not offer a Replaces transfer without
// `Supported: replaces` — so onUpdate() and onRefer()'s ?Replaces= splice were
// both unreachable from a spec-abiding phone. The OPTIONS test below pins both
// the presence of the true capabilities and the ABSENCE of the ones this PBX
// does not implement.

#include <gtest/gtest.h>

#include <string>
#include <utility>
#include <vector>

#include "RequestsHandler.hpp"

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#else
#include <arpa/inet.h>
#endif

namespace
{
	constexpr const char* kServerIp = "192.168.40.1";

	sockaddr_in addrFor(const std::string& ip, uint16_t port = 5060)
	{
		sockaddr_in a{};
		a.sin_family = AF_INET;
		a.sin_addr.s_addr = inet_addr(ip.c_str());
		a.sin_port = htons(port);
		return a;
	}

	std::shared_ptr<SipMessage> makeRegister(const std::string& ext, const std::string& ip,
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
		return RequestsHandler::getMessageFromPool(raw, addrFor(ip));
	}

	std::string sdpBody(const std::string& ip)
	{
		return
			"v=0\r\n"
			"o=- 0 0 IN IP4 " + ip + "\r\n"
			"s=-\r\n"
			"c=IN IP4 " + ip + "\r\n"
			"t=0 0\r\n"
			"m=audio 10000 RTP/AVP 0\r\n"
			"a=rtpmap:0 PCMU/8000\r\n";
	}

	// One complete direct call: 100 (caller) INVITEs 106 (callee), 106 answers
	// with the supplied Session-Expires line (pass "" for none). Returns the
	// Session the PBX holds afterwards, so a test can read the timer state off
	// it. The exchange deliberately goes through handle() end to end rather than
	// poking armSessionTimer(), because the whole point of #198 is which leg's
	// 200 OK the header is read from and who the UAC of that leg is.
	std::shared_ptr<Session> runCallAnsweredWith(RequestsHandler& handler,
	                                             const std::string& callId,
	                                             const std::string& sessionExpiresLine)
	{
		const std::string callerIp = "192.168.40.10";
		const std::string calleeIp = "192.168.40.20";

		{
			std::string body = sdpBody(callerIp);
			std::string raw =
				"INVITE sip:106@server SIP/2.0\r\n"
				"Via: SIP/2.0/UDP " + callerIp + ":5060;branch=z9hG4bKi" + callId + "\r\n"
				"From: <sip:100@server>;tag=ctag" + callId + "\r\n"
				"To: <sip:106@server>\r\n"
				"Call-ID: " + callId + "\r\n"
				"CSeq: 1 INVITE\r\n"
				"Max-Forwards: 70\r\n"
				"Contact: <sip:100@" + callerIp + ":5060>\r\n"
				"Supported: timer\r\n"
				"Session-Expires: 1800\r\n"
				"Min-SE: 90\r\n"
				"Content-Type: application/sdp\r\n"
				"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
			handler.handle(RequestsHandler::getMessageFromPool(raw, addrFor(callerIp)));
		}

		{
			std::string body = sdpBody(calleeIp);
			std::string raw =
				"SIP/2.0 200 OK\r\n"
				"Via: SIP/2.0/UDP " + callerIp + ":5060;branch=z9hG4bKi" + callId + "\r\n"
				"From: <sip:100@server>;tag=ctag" + callId + "\r\n"
				"To: <sip:106@server>;tag=etag" + callId + "\r\n"
				"Call-ID: " + callId + "\r\n"
				"CSeq: 1 INVITE\r\n"
				"Contact: <sip:106@" + calleeIp + ":5060>\r\n" +
				sessionExpiresLine +
				"Content-Type: application/sdp\r\n"
				"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
			handler.handle(RequestsHandler::getMessageFromPool(raw, addrFor(calleeIp)));
		}

		auto s = handler.getSession("Call-ID: " + callId);
		return s.has_value() ? s.value() : nullptr;
	}

	// Registers the two extensions every session-timer test uses.
	void registerBothLegs(RequestsHandler& handler)
	{
		handler.handle(makeRegister("100", "192.168.40.10", "reg-100"));
		handler.handle(makeRegister("106", "192.168.40.20", "reg-106"));
	}

	std::string firstMatching(const std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>>& sent,
	                          const std::string& needle)
	{
		for (const auto& [addr, msg] : sent)
		{
			(void)addr;
			std::string raw = msg ? msg->toString() : std::string{};
			if (raw.find(needle) != std::string::npos) return raw;
		}
		return {};
	}

	// The value of the first header line whose name matches, header name stripped.
	std::string headerValue(const std::string& raw, const std::string& name)
	{
		size_t pos = 0;
		while (pos < raw.size())
		{
			size_t eol = raw.find("\r\n", pos);
			if (eol == std::string::npos) eol = raw.size();
			if (eol == pos) break;   // blank line: end of the header block
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
}

// ── RFC 4028 §7.4: the arming decision, one test per refresher shape ─────────

TEST(SessionTimer, RefresherUasArmsTheReaperAndDoesNotMakeThePbxTheRefresher)
{
	std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>> sent;
	RequestsHandler handler(kServerIp, 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});
	registerBothLegs(handler);

	auto session = runCallAnsweredWith(handler, "timer-uas",
		"Session-Expires: 1800;refresher=uas\r\n");
	ASSERT_TRUE(session != nullptr);
	ASSERT_EQ(session->getState(), Session::State::Connected)
		<< "the call must connect normally regardless of the timer decision";

	// refresher=uas designates the CALLEE, which is a real phone that will send
	// its refresh through us (onInvite() rewrote Contact to the PBX, so the
	// re-INVITE lands on onReinvite() and re-arms). Arming is correct here.
	EXPECT_EQ(session->getSessionExpiresSeconds(), 1800u)
		<< "a 2xx naming the callee as refresher must arm the expiry reaper";

	// The #198 inversion: the old `weRefresh = (ref == "uas")` recorded the PBX
	// as the refresher in exactly this case. The PBX is not a UA of this dialog
	// at all — it relayed the caller's INVITE — so this must be false, and the
	// firmware must never believe it owes a refresh it has no code to send.
	EXPECT_FALSE(session->isRefresher())
		<< "refresher=uas names the CALLEE (RFC 4028 §7.4), never this PBX";
}

TEST(SessionTimer, RefresherUacArmsTheReaperAndDoesNotMakeThePbxTheRefresher)
{
	std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>> sent;
	RequestsHandler handler(kServerIp, 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});
	registerBothLegs(handler);

	auto session = runCallAnsweredWith(handler, "timer-uac",
		"Session-Expires: 1800;refresher=uac\r\n");
	ASSERT_TRUE(session != nullptr);
	ASSERT_EQ(session->getState(), Session::State::Connected);

	// refresher=uac designates the party that SENT the INVITE. On this PBX that
	// is the CALLER'S PHONE, not the PBX: onInvite() forwards a clone of the
	// caller's own INVITE, keeping its From/To/Call-ID/CSeq. The caller's
	// refresh also arrives here (the 200 OK relay rewrote Contact to us), so the
	// reaper is serviceable and arming is correct.
	EXPECT_EQ(session->getSessionExpiresSeconds(), 1800u)
		<< "a 2xx naming the caller as refresher must still arm the reaper — the "
		   "caller's re-INVITE is relayed through this PBX and re-arms it";
	EXPECT_FALSE(session->isRefresher())
		<< "refresher=uac names the CALLER'S PHONE; this PBX originated no INVITE";
}

TEST(SessionTimer, NoRefresherParameterDoesNotArmTheReaper)
{
	std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>> sent;
	RequestsHandler handler(kServerIp, 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});
	registerBothLegs(handler);

	auto session = runCallAnsweredWith(handler, "timer-none",
		"Session-Expires: 1800\r\n");
	ASSERT_TRUE(session != nullptr);

	// RFC 4028's UAS rules require a refresher parameter on any 2xx that carries
	// Session-Expires. Without one nobody is obliged to refresh, so the reaper
	// could only ever fire as a spurious BYE on a healthy call. Decline to arm.
	EXPECT_EQ(session->getSessionExpiresSeconds(), 0u)
		<< "Session-Expires with no refresher must NOT arm an expiry reaper";

	// Declining the timer must not disturb the call itself, and must not cost
	// the dialog headers — attended transfer and the #72 BYE guard both read
	// them, which is why armSessionTimer() captures them before it decides.
	EXPECT_EQ(session->getState(), Session::State::Connected);
	EXPECT_FALSE(session->getDialogFrom().empty())
		<< "dialog From must be captured even when the reaper is declined";
	EXPECT_FALSE(session->getDialogTo().empty())
		<< "dialog To must be captured even when the reaper is declined";
}

TEST(SessionTimer, NoSessionExpiresHeaderArmsNothing)
{
	// The baseline the two armed cases are measured against: a plain 200 OK with
	// no RFC 4028 headers at all leaves the reaper disarmed, as it always has.
	std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>> sent;
	RequestsHandler handler(kServerIp, 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});
	registerBothLegs(handler);

	auto session = runCallAnsweredWith(handler, "timer-absent", "");
	ASSERT_TRUE(session != nullptr);
	EXPECT_EQ(session->getSessionExpiresSeconds(), 0u);
	EXPECT_FALSE(session->isRefresher());
}

// ── Issue #199 root cause 2: capability advertisement on OPTIONS ─────────────

TEST(SessionTimer, OptionsAdvertisesTheMethodsAndOptionTagsThisPbxReallyHandles)
{
	std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>> sent;
	RequestsHandler handler(kServerIp, 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	// A bare OPTIONS carrying no capability headers of its own, so every header
	// asserted below is one the PBX produced rather than one it echoed back.
	const std::string phoneIp = "192.168.40.30";
	std::string raw =
		"OPTIONS sip:server SIP/2.0\r\n"
		"Via: SIP/2.0/UDP " + phoneIp + ":5060;branch=z9hG4bKopt\r\n"
		"From: <sip:100@server>;tag=opttag\r\n"
		"To: <sip:server@server>\r\n"
		"Call-ID: options-199\r\n"
		"CSeq: 1 OPTIONS\r\n"
		"Max-Forwards: 70\r\n"
		"Content-Length: 0\r\n\r\n";
	handler.handle(RequestsHandler::getMessageFromPool(raw, addrFor(phoneIp)));

	const std::string ok = firstMatching(sent, "SIP/2.0 200 OK");
	ASSERT_FALSE(ok.empty()) << "OPTIONS produced no 200 OK";

	const std::string allow = headerValue(ok, "Allow");
	ASSERT_FALSE(allow.empty())
		<< "RFC 3261 §11.2: a 200 OK to OPTIONS must advertise Allow\n" << ok;

	// Every method initHandlers() dispatches, plus INFO (handled ahead of the
	// table). UPDATE is the one RFC 3311 §5.1 gates on: without it here, a
	// compliant phone never sends the UPDATE that onUpdate() has always handled.
	for (const char* m : {"INVITE", "ACK", "CANCEL", "BYE", "OPTIONS", "REGISTER",
	                      "INFO", "MESSAGE", "REFER", "SUBSCRIBE", "UPDATE"})
	{
		EXPECT_NE(allow.find(m), std::string::npos)
			<< "Allow omits " << m << ", which this PBX dispatches: " << allow;
	}

	// ...and nothing aspirational. There is no PRACK handler and nothing accepts
	// an inbound NOTIFY, so a phone must not be told to send either.
	EXPECT_EQ(allow.find("PRACK"), std::string::npos)
		<< "Allow claims PRACK; no handler exists for it: " << allow;
	EXPECT_EQ(allow.find("NOTIFY"), std::string::npos)
		<< "Allow claims NOTIFY; BlfSubscriptions only SENDS them: " << allow;
	EXPECT_EQ(allow.find("PUBLISH"), std::string::npos) << allow;

	// RFC 3891 §4: a phone offers a Replaces-based attended transfer only when
	// the peer advertised the option tag. onRefer()'s ?Replaces= splice was
	// unreachable from a compliant phone without this.
	const std::string supported = headerValue(ok, "Supported");
	ASSERT_FALSE(supported.empty()) << ok;
	EXPECT_NE(supported.find("replaces"), std::string::npos)
		<< "Supported omits \"replaces\" (RFC 3891 §4): " << supported;

	// Over-claiming here is the #199 failure mode itself. "timer" needs Min-SE
	// processing and a 422 response (RFC 4028 §5/§6) that this PBX does not
	// implement — getMinSESecs() has no caller — and "100rel" needs PRACK.
	EXPECT_EQ(supported.find("timer"), std::string::npos)
		<< "Supported claims \"timer\" but no 422/Min-SE handling exists: " << supported;
	EXPECT_EQ(supported.find("100rel"), std::string::npos)
		<< "Supported claims \"100rel\" but there is no PRACK handler: " << supported;

	// Bodies the PBX genuinely parses, and the one SUBSCRIBE package it accepts.
	const std::string accept = headerValue(ok, "Accept");
	EXPECT_NE(accept.find("application/sdp"), std::string::npos) << ok;
	EXPECT_NE(headerValue(ok, "Allow-Events").find("dialog"), std::string::npos) << ok;
}
