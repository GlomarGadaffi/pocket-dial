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

// ── Slot recycling must not leak per-call state (issue #353) ─────────────────
//
// Sessions are pooled: allocateSession() finds a slot whose Call-ID is no
// longer live and calls reset() on it. So reset() and release() are what make
// a recycled slot indistinguishable from a fresh one, and any per-call field
// that survives them leaks into the next caller.
//
// This bit for real. _isVoicemail had no clearing writer anywhere in the tree
// -- two sites set it true, nothing ever set it false -- so one voicemail call
// permanently marked its pool slot, and endCall()'s
//
//     if (ending->isVoicemail()) releaseVoicemailLeg(getVoicemailLegSlot())
//
// then tore down a leg index belonging to somebody else's live deposit.
//
// These tests assert the general property rather than the two fields that
// happened to be wrong, so the next field added to Session is covered by the
// test that already exists instead of the one nobody wrote.

TEST(SessionRecycling, ResetClearsVoicemailStateSoTheNextCallIsNotMistakenForOne)
{
	Session s("call-vm-1", nullptr);
	s.setVoicemail(true);
	s.setVoicemailLegSlot(2);
	s.setVoicemailPurpose(Session::VoicemailPurpose::Retrieval);

	s.reset("call-ordinary-2", nullptr);

	EXPECT_FALSE(s.isVoicemail())
		<< "a recycled slot that once served voicemail must not still claim to be one";
	EXPECT_EQ(s.getVoicemailLegSlot(), -1)
		<< "endCall() releases this index; a stale one tears down another call's leg";
	EXPECT_EQ(s.getVoicemailPurpose(), Session::VoicemailPurpose::Deposit)
		<< "purpose drives tick()'s menu advance and must not survive either";
}

// The other half of the contract, and the one that is counter-intuitive
// enough to need pinning: release() must NOT clear this state.
//
// endCall() releases the pool slot first and only afterwards asks
// ending->isVoicemail() / getVoicemailLegSlot() so it can hand the media leg
// back. Clearing in release() wipes the flag before its reader runs and
// orphans the leg. That is not hypothetical -- it is what the first version of
// the #353 fix did, and four VoicemailDivert tests went red on it.
TEST(SessionRecycling, ReleaseDeliberatelyPreservesVoicemailStateForEndCall)
{
	Session s("call-vm-3", nullptr);
	s.setVoicemail(true);
	s.setVoicemailLegSlot(1);

	s.release();

	EXPECT_TRUE(s.isVoicemail())
		<< "endCall() reads this AFTER release() to hand the media leg back";
	EXPECT_EQ(s.getVoicemailLegSlot(), 1)
		<< "clearing here orphans the leg; reset() is the recycling path, not this";
}

TEST(SessionRecycling, ResetClearsTrunkStateSoARelayPairIsNotReleasedTwice)
{
	Session s("call-trunk-1", nullptr);
	s.setTrunk(true);
	s.setTrunkRelaySlot(1);

	s.reset("call-ordinary-4", nullptr);

	EXPECT_FALSE(s.isTrunk())
		<< "a stale trunk flag makes the session-timer sweep skip an ordinary call";
	EXPECT_EQ(s.getTrunkRelaySlot(), -1)
		<< "endCall() releases this pair; a stale index frees somebody else's relay";
}

// Same contract for the trunk pair: endCall() will read these after release()
// to give the relay receivers back, so release() leaves them alone.
TEST(SessionRecycling, ReleaseDeliberatelyPreservesTrunkStateForEndCall)
{
	Session s("call-trunk-2", nullptr);
	s.setTrunk(true);
	s.setTrunkRelaySlot(0);

	s.release();

	EXPECT_TRUE(s.isTrunk());
	EXPECT_EQ(s.getTrunkRelaySlot(), 0);
}

// The property itself, stated once: a reset slot is a fresh slot. Written
// against a session carrying BOTH kinds of per-call state at once, because the
// real pool has no idea what the previous caller did with it.
TEST(SessionRecycling, AResetSlotIsIndistinguishableFromAFreshOne)
{
	const Session fresh("call-fresh", nullptr);

	Session used("call-used", nullptr);
	used.setVoicemail(true);
	used.setVoicemailLegSlot(3);
	used.setVoicemailPurpose(Session::VoicemailPurpose::Retrieval);
	used.setTrunk(true);
	used.setTrunkRelaySlot(2);
	used.noteServerCSeq(7);
	used.noteObservedCSeq(40);
	used.reset("call-fresh", nullptr);

	EXPECT_EQ(used.isVoicemail(),          fresh.isVoicemail());
	EXPECT_EQ(used.getVoicemailLegSlot(),  fresh.getVoicemailLegSlot());
	EXPECT_EQ(used.getVoicemailPurpose(),  fresh.getVoicemailPurpose());
	EXPECT_EQ(used.isTrunk(),              fresh.isTrunk());
	EXPECT_EQ(used.getTrunkRelaySlot(),    fresh.getTrunkRelaySlot());
	// #389: a stale server CSeq would push a recycled slot's first BYE off 2.
	EXPECT_EQ(used.lastServerCSeq(),       fresh.lastServerCSeq());
	EXPECT_EQ(used.maxObservedCSeq(),      fresh.maxObservedCSeq());
	EXPECT_EQ(used.nextServerCSeq(),       fresh.nextServerCSeq());
}

// Issue #402: the server's next CSeq on a dialog goes above EVERYTHING used on
// it -- its own requests and either party's -- whichever of the two is higher.
TEST(SessionRecycling, NextServerCSeqGoesAboveBothServerAndObservedCSeqs)
{
	Session s("call-402", nullptr);
	EXPECT_EQ(s.nextServerCSeq(), 2u);         // nothing known: the long-standing 2

	s.noteObservedCSeq(23670);                  // e.g. a phone's hold re-INVITE
	EXPECT_EQ(s.nextServerCSeq(), 23671u);

	s.noteServerCSeq(3);                        // a lower server CSeq doesn't pull it down
	EXPECT_EQ(s.nextServerCSeq(), 23671u);

	s.noteServerCSeq(23671);                    // after the server uses it
	EXPECT_EQ(s.nextServerCSeq(), 23672u);

	s.noteObservedCSeq(100);                    // observations never move it backwards
	EXPECT_EQ(s.maxObservedCSeq(), 23670u);
	EXPECT_EQ(s.nextServerCSeq(), 23672u);
}

// #402 review: RFC 3261 s8.1.1.5 caps CSeq below 2^31. A forged 4294967295 must
// not be recorded (it would wrap nextServerCSeq() to 0), and the server's next
// CSeq must stay legal -- never 0, never >= 2^31 -- even at the ceiling.
TEST(SessionRecycling, ServerCSeqIgnoresIllegalValuesAndNeverWraps)
{
	const uint32_t limit = Session::kCSeqLimit;   // 2^31

	Session s("call-402-forged", nullptr);
	s.noteObservedCSeq(4294967295u);
	s.noteObservedCSeq(limit);
	s.noteObservedCSeq(0);
	EXPECT_EQ(s.maxObservedCSeq(), 0u) << "values at/above 2^31 (and 0) are not CSeqs any UA may send";
	EXPECT_EQ(s.nextServerCSeq(), 2u);

	s.noteServerCSeq(4294967295u);
	EXPECT_EQ(s.lastServerCSeq(), 0u);

	s.noteObservedCSeq(limit - 1);              // the largest legal value
	EXPECT_EQ(s.nextServerCSeq(), limit - 1) << "saturates at 2^31-1 rather than wrapping";
	EXPECT_NE(s.nextServerCSeq(), 0u);
}

// ── Issue #198: RFC 4028 422 floor and tick-driven expiry ────────────────────

#include "SessionTimer.hpp"

TEST(SessionTimer, MinSEFor422DecisionTable)
{
	EXPECT_EQ(pbx::sessionIntervalMinSEFor422(0, 0), 0u) << "no Session-Expires: nothing to reject";
	EXPECT_EQ(pbx::sessionIntervalMinSEFor422(90, 0), 0u) << "exactly the floor is accepted";
	EXPECT_EQ(pbx::sessionIntervalMinSEFor422(1800, 90), 0u);
	EXPECT_EQ(pbx::sessionIntervalMinSEFor422(89, 0), 90u);
	EXPECT_EQ(pbx::sessionIntervalMinSEFor422(30, 60), 90u);
	EXPECT_EQ(pbx::sessionIntervalMinSEFor422(30, 120), 120u) << "the request's larger Min-SE wins";
}

TEST(SessionTimer, TooSmallSessionExpiresOnInviteIsAnswered422WithMinSE)
{
	std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>> sent;
	RequestsHandler handler(kServerIp, 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});
	registerBothLegs(handler);
	sent.clear();

	const std::string ip = "192.168.40.10";
	const std::string body = sdpBody(ip);
	const std::string raw =
		"INVITE sip:106@server SIP/2.0\r\n"
		"Via: SIP/2.0/UDP " + ip + ":5060;branch=z9hG4bKsmall\r\n"
		"From: <sip:100@server>;tag=ctagsmall\r\n"
		"To: <sip:106@server>\r\n"
		"Call-ID: timer-small\r\n"
		"CSeq: 1 INVITE\r\n"
		"Max-Forwards: 70\r\n"
		"Contact: <sip:100@" + ip + ":5060>\r\n"
		"Supported: timer\r\n"
		"Session-Expires: 30\r\n"
		"Content-Type: application/sdp\r\n"
		"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
	handler.handle(RequestsHandler::getMessageFromPool(raw, addrFor(ip)));

	const std::string resp = firstMatching(sent, "SIP/2.0 422");
	ASSERT_FALSE(resp.empty()) << "Session-Expires below 90 must be refused 422 (RFC 4028 §8.1)";
	EXPECT_EQ(headerValue(resp, "Min-SE"), "90");
	EXPECT_TRUE(firstMatching(sent, "INVITE sip:").empty()) << "the INVITE must not reach the callee";
	EXPECT_FALSE(handler.getSession("Call-ID: timer-small").has_value()) << "no session allocated";
}

namespace
{
	// A `method` request from `from` at `ip` to `to` carrying the header lines
	// `extra` verbatim. An INVITE carries an SDP offer; an UPDATE is bodiless
	// (a session refresh).
	std::shared_ptr<SipMessage> timerRequest(const std::string& method, const std::string& from,
	                                         const std::string& ip, const std::string& to,
	                                         const std::string& callId, const std::string& extra,
	                                         const std::string& toTag = "", int cseq = 1)
	{
		const bool withSdp = method == "INVITE";
		const std::string body = withSdp ? sdpBody(ip) : std::string();
		const std::string raw =
			method + " sip:" + to + "@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + ip + ":5060;branch=z9hG4bK" + callId + method + std::to_string(cseq) + "\r\n"
			"From: <sip:" + from + "@server>;tag=ctag" + callId + "\r\n"
			"To: <sip:" + to + "@server>" + (toTag.empty() ? "" : ";tag=" + toTag) + "\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: " + std::to_string(cseq) + " " + method + "\r\n"
			"Max-Forwards: 70\r\n"
			"Contact: <sip:" + from + "@" + ip + ":5060>\r\n" + extra +
			(withSdp ? "Content-Type: application/sdp\r\n" : "") +
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		return RequestsHandler::getMessageFromPool(raw, addrFor(ip));
	}

	// An INVITE from 100 to `to` carrying `seLine` (e.g. "Session-Expires: 30").
	std::shared_ptr<SipMessage> makeTimerInvite(const std::string& to, const std::string& callId,
	                                            const std::string& seLine,
	                                            const std::string& toTag = "", int cseq = 1)
	{
		return timerRequest("INVITE", "100", "192.168.40.10", to, callId,
			"Supported: timer\r\n" + seLine + "\r\n", toTag, cseq);
	}
}

TEST(SessionTimer, CompactFormSessionExpiresIsAlsoHeld422)
{
	std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>> sent;
	RequestsHandler handler(kServerIp, 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});
	registerBothLegs(handler);
	sent.clear();
	handler.handle(makeTimerInvite("106", "timer-compact", "x: 30"));
	EXPECT_FALSE(firstMatching(sent, "SIP/2.0 422").empty()) << "compact 'x:' is Session-Expires (RFC 4028 §4)";
}

TEST(SessionTimer, EmergencyCallsAreNever422dForAShortSessionExpires)
{
	for (const char* number : {"911", "933"})
	{
		std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>> sent;
		RequestsHandler handler(kServerIp, 5060,
			[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
				sent.emplace_back(addr, std::move(msg));
			});
		registerBothLegs(handler);
		sent.clear();
		handler.handle(makeTimerInvite(number, std::string("timer-e") + number, "Session-Expires: 30"));
		EXPECT_TRUE(firstMatching(sent, "SIP/2.0 422").empty()) << number << " must never be bounced 422";
		// Positive: it reached routeEmergencyCall() (no route on this handler, so its 503).
		EXPECT_FALSE(firstMatching(sent, "SIP/2.0 503 Emergency Call Not Routable").empty())
			<< number << " must reach routeEmergencyCall()";
	}
}

TEST(SessionTimer, ReinviteWithShortSessionExpiresIsNot422d)
{
	std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>> sent;
	RequestsHandler handler(kServerIp, 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});
	registerBothLegs(handler);
	auto session = runCallAnsweredWith(handler, "timer-reinv", "Session-Expires: 1800;refresher=uac\r\n");
	ASSERT_TRUE(session != nullptr);
	ASSERT_EQ(session->getState(), Session::State::Connected);
	sent.clear();
	handler.handle(makeTimerInvite("106", "timer-reinv", "Session-Expires: 30", "etagtimer-reinv", 2));
	EXPECT_TRUE(firstMatching(sent, "SIP/2.0 422").empty())
		<< "the floor applies to the initial INVITE only; re-INVITEs go to onReinvite()";
	EXPECT_FALSE(sent.empty()) << "the re-INVITE must still be handled, not dropped";
}

TEST(SessionTimer, ExpiryDrivenByTickByesEachLegExactlyOnce)
{
	std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>> sent;
	RequestsHandler handler(kServerIp, 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});
	registerBothLegs(handler);

	auto session = runCallAnsweredWith(handler, "timer-expire",
		"Session-Expires: 1800;refresher=uac\r\n");
	ASSERT_TRUE(session != nullptr);
	ASSERT_EQ(session->getSessionExpiresSeconds(), 1800u);

	// Backdate the arm so the interval has already elapsed with no refresh.
	session->armSessionTimer(1800, false, std::chrono::steady_clock::now() - std::chrono::seconds(1801));
	sent.clear();

	auto countByes = [&](const std::string& ip) {
		int n = 0;
		for (const auto& [addr, msg] : sent)
		{
			if (!msg || addr.sin_addr.s_addr != inet_addr(ip.c_str())) continue;
			if (msg->toString().rfind("BYE ", 0) == 0) ++n;
		}
		return n;
	};

	handler.tick();
	EXPECT_EQ(countByes("192.168.40.10"), 1) << "caller leg BYEd exactly once";
	EXPECT_EQ(countByes("192.168.40.20"), 1) << "callee leg BYEd exactly once";

	handler.tick();
	EXPECT_EQ(countByes("192.168.40.10"), 1) << "a second tick must not re-BYE";
	EXPECT_EQ(countByes("192.168.40.20"), 1);
}

// ── Issue #198: the Session-Expires on a 2xx the PBX writes itself ───────────
//
// Every answer below is built by cloning the phone's request, so before this
// change it echoed the phone's own `Session-Expires: 1800` back with no
// refresher parameter. RFC 4028 §9 requires one on any 2xx that carries the
// header, and without it nobody is named to refresh. The PBX never sends a
// refresh, so the only honest answer is refresher=uac (the phone refreshes,
// and the PBX answers it), with the `Require: timer` §9 makes mandatory.

namespace
{
	using Sent = std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>>;

	constexpr const char* kCaller = "192.168.40.10";   // 100
	constexpr const char* kOther  = "192.168.40.20";   // 106

	// What pjsua sends on an initial INVITE (tests/interop logs): the phone
	// supports timer and asks for 1800 s without naming a refresher.
	constexpr const char* kTimerOffer = "Supported: timer\r\nSession-Expires: 1800\r\nMin-SE: 90\r\n";

	// The last 200 OK sent to `ip` whose CSeq value is `cseq` (e.g. "1 INVITE").
	std::string okTo(const Sent& sent, const std::string& ip, const std::string& cseq)
	{
		std::string found;
		for (const auto& [addr, msg] : sent)
		{
			if (!msg || addr.sin_addr.s_addr != inet_addr(ip.c_str())) continue;
			const std::string raw = msg->toString();
			if (raw.rfind("SIP/2.0 200 OK", 0) == 0 && headerValue(raw, "CSeq") == cseq) found = raw;
		}
		return found;
	}

	std::string toTagOf(const std::string& ok)
	{
		const std::string to = headerValue(ok, "To");
		const size_t p = to.find(";tag=");
		return p == std::string::npos ? std::string{} : to.substr(p + 5);
	}

	// Header lines in `raw` whose name is exactly `name` (no compact-form folding).
	int linesNamed(const std::string& raw, const std::string& name)
	{
		int n = 0;
		for (size_t p = raw.find("\r\n" + name + ":"); p != std::string::npos;
		     p = raw.find("\r\n" + name + ":", p + 2))
		{
			++n;
		}
		return n;
	}

	void expectPhoneRefreshes(const std::string& ok, const std::string& what)
	{
		ASSERT_FALSE(ok.empty()) << what << ": the PBX sent no 200 OK";
		EXPECT_EQ(headerValue(ok, "Session-Expires"), "1800;refresher=uac")
			<< what << ": RFC 4028 §9 needs a refresher, and the PBX never refreshes\n" << ok;
		EXPECT_EQ(linesNamed(ok, "Session-Expires"), 1) << what << ": exactly one, ours\n" << ok;
		EXPECT_EQ(headerValue(ok, "Require"), "timer")
			<< what << ": RFC 4028 §9 requires Require: timer with refresher=uac\n" << ok;
	}

	struct Rig
	{
		Sent sent;
		RequestsHandler handler{kServerIp, 5060,
			[this](const sockaddr_in& a, std::shared_ptr<SipMessage> m) { sent.emplace_back(a, std::move(m)); }};
		Rig() { registerBothLegs(handler); }
	};
}

TEST(SessionTimer, The777AnswerNamesThePhoneAsRefresher)
{
	Rig r;
	r.handler.handle(timerRequest("INVITE", "100", kCaller, "777", "se-777", kTimerOffer));
	expectPhoneRefreshes(okTo(r.sent, kCaller, "1 INVITE"), "777 answer");
}

TEST(SessionTimer, TheConferenceAnswerNamesThePhoneAsRefresher)
{
	Rig r;
	r.handler.handle(timerRequest("INVITE", "100", kCaller, "888", "se-888", kTimerOffer));
	expectPhoneRefreshes(okTo(r.sent, kCaller, "1 INVITE"), "888 answer");
}

TEST(SessionTimer, TheAnchorAnswerAndItsReinviteAnswerNameThePhoneAsRefresher)
{
	Rig r;
	r.handler.handle(timerRequest("INVITE", "100", kCaller, "555", "se-555", kTimerOffer));
	const std::string ok = okTo(r.sent, kCaller, "1 INVITE");
	expectPhoneRefreshes(ok, "555 answer");

	// The phone's refresh by re-INVITE, answered by answerAnchorReinvite().
	r.handler.handle(timerRequest("INVITE", "100", kCaller, "555", "se-555",
		"Supported: timer\r\nSession-Expires: 1800;refresher=uac\r\n", toTagOf(ok), 2));
	expectPhoneRefreshes(okTo(r.sent, kCaller, "2 INVITE"), "555 re-INVITE answer");
}

TEST(SessionTimer, TheParkAndRetrieveAnswersNameThePhoneAsRefresher)
{
	Rig r;
	r.handler.handle(timerRequest("INVITE", "100", kCaller, "700", "se-park", kTimerOffer));
	expectPhoneRefreshes(okTo(r.sent, kCaller, "1 INVITE"), "park answer");

	r.handler.handle(timerRequest("INVITE", "106", kOther, "700", "se-retrieve", kTimerOffer));
	expectPhoneRefreshes(okTo(r.sent, kOther, "1 INVITE"), "retrieve answer");
}

TEST(SessionTimer, TheLocalRefreshAnswerNamesThePhoneAsRefresher)
{
	Rig r;
	r.handler.handle(timerRequest("INVITE", "100", kCaller, "777", "se-777-upd", kTimerOffer));
	const std::string ok = okTo(r.sent, kCaller, "1 INVITE");
	ASSERT_FALSE(ok.empty()) << "precondition: 777 answers";

	// The refresh UPDATE pjsua sends at half the interval, which answerRefreshLocally() answers.
	r.handler.handle(timerRequest("UPDATE", "100", kCaller, "777", "se-777-upd",
		"Supported: timer\r\nSession-Expires: 1800;refresher=uac\r\n", toTagOf(ok), 2));
	expectPhoneRefreshes(okTo(r.sent, kCaller, "2 UPDATE"), "refresh UPDATE answer");
}

TEST(SessionTimer, ACompactSessionExpiresIsAnsweredOnceInFullForm)
{
	Rig r;
	r.handler.handle(timerRequest("INVITE", "100", kCaller, "777", "se-compact", "k: timer\r\nx: 1800\r\n"));
	const std::string ok = okTo(r.sent, kCaller, "1 INVITE");
	expectPhoneRefreshes(ok, "compact-form offer");
	EXPECT_EQ(linesNamed(ok, "x"), 0) << "the phone's own compact line must not survive beside ours\n" << ok;
}

TEST(SessionTimer, AnAnswerCarriesNoTimerThePhoneCannotBeTheRefresherOf)
{
	struct Case { const char* callId; const char* headers; const char* why; };
	const Case cases[] = {
		{"se-nosup", "Session-Expires: 1800\r\nRequire: timer\r\n",
		 "no Supported: timer, so refresher=uac is not the phone's to accept (RFC 4028 §9)"},
		{"se-uas", "Supported: timer\r\nSession-Expires: 1800;refresher=uas\r\n",
		 "refresher=uas names the PBX, which never sends a refresh"},
	};
	for (const Case& c : cases)
	{
		Rig r;
		r.handler.handle(timerRequest("INVITE", "100", kCaller, "777", c.callId, c.headers));
		const std::string ok = okTo(r.sent, kCaller, "1 INVITE");
		// Positive control: the call is still answered, by 777.
		ASSERT_FALSE(ok.empty()) << c.callId << ": the call must still be answered";
		EXPECT_NE(headerValue(ok, "Contact").find("sip:777@"), std::string::npos) << c.callId << "\n" << ok;
		// No Session-Expires is RFC 4028 §7.2's "no session expiration".
		EXPECT_EQ(linesNamed(ok, "Session-Expires"), 0) << c.callId << ": " << c.why << "\n" << ok;
		EXPECT_EQ(linesNamed(ok, "Require"), 0) << c.callId << ": no timer, so no Require: timer\n" << ok;
	}
}
