// Wire-level tests for the BLF/dialog-info subscription machine
// (src/SIP/BlfSubscriptions.cpp): the event-package gate, the 202 Accepted, and
// the header shape of the NOTIFY it mints inside the subscription dialog.

#include <gtest/gtest.h>

#include "BlfSubscriptions.hpp"
#include "FakePbxEnv.hpp"

namespace
{
	std::shared_ptr<SipMessage> subscribe(const std::string& watcher, const std::string& target,
		const std::string& callId, const std::string& eventHdr, int expires,
		const sockaddr_in& src)
	{
		std::string raw =
			"SUBSCRIBE sip:" + target + "@192.168.1.10 SIP/2.0\r\n"
			"Via: SIP/2.0/UDP 192.168.1.60:5060;branch=z9hG4bKwatch\r\n"
			"From: <sip:" + watcher + "@192.168.1.10>;tag=watchertag\r\n"
			"To: <sip:" + target + "@192.168.1.10>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 SUBSCRIBE\r\n";
		if (!eventHdr.empty()) raw += eventHdr + "\r\n";
		raw += "Expires: " + std::to_string(expires) + "\r\n"
			   "Content-Length: 0\r\n\r\n";
		return std::make_shared<SipMessage>(raw, src);
	}
}

TEST(BlfSubscriptions, AcceptsDialogSubscribeAndNotifiesWithSwappedDialogRoles)
{
	FakePbxEnv env;
	BlfSubscriptions blf(env);
	const sockaddr_in watcherAddr = FakePbxEnv::addr("192.168.1.60", 5060);

	blf.onSubscribe(subscribe("200", "101", "watch-1@192.168.1.60", "Event: dialog", 3600,
		watcherAddr));

	ASSERT_EQ(env.sent.size(), 2u);          // 202 Accepted, then the initial NOTIFY
	EXPECT_NE(env.sentRaw(0).find("202 Accepted"), std::string::npos) << env.sentRaw(0);

	const std::string notify = env.sentRaw(1);
	EXPECT_EQ(notify.rfind("NOTIFY sip:192.168.1.60:5060", 0), 0u) << notify;
	// Exactly one From/To/Call-ID, each a bare value under the right name.
	EXPECT_EQ(FakePbxEnv::countOf(notify, "From:"), 1) << notify;
	EXPECT_EQ(FakePbxEnv::countOf(notify, "To:"), 1) << notify;
	EXPECT_EQ(FakePbxEnv::countOf(notify, "Call-ID:"), 1) << notify;
	EXPECT_EQ(notify.find("From: To:"), std::string::npos) << notify;
	EXPECT_EQ(notify.find("To: From:"), std::string::npos) << notify;
	// RFC 6665 §4.4.1: roles swap — our To (with our tag) becomes the NOTIFY From.
	EXPECT_NE(notify.find("From: <sip:101@192.168.1.10>;tag="), std::string::npos) << notify;
	EXPECT_NE(notify.find("To: <sip:200@192.168.1.10>;tag=watchertag"), std::string::npos)
		<< notify;
	EXPECT_NE(notify.find("Call-ID: watch-1@192.168.1.60\r\n"), std::string::npos) << notify;
	EXPECT_NE(notify.find("Subscription-State: active;expires="), std::string::npos) << notify;
	// Idle target: dialog-info document carries no <dialog> element.
	EXPECT_NE(notify.find("application/dialog-info+xml"), std::string::npos) << notify;
	EXPECT_EQ(notify.find("<dialog "), std::string::npos) << notify;
}

// Only the RFC 4235 "dialog" package is implemented; anything else is 489.
TEST(BlfSubscriptions, RejectsUnsupportedEventPackage)
{
	FakePbxEnv env;
	BlfSubscriptions blf(env);
	const sockaddr_in watcherAddr = FakePbxEnv::addr("192.168.1.60", 5060);

	blf.onSubscribe(subscribe("200", "101", "watch-2@192.168.1.60", "Event: presence", 3600,
		watcherAddr));

	ASSERT_EQ(env.sent.size(), 1u);
	EXPECT_NE(env.sentRaw(0).find("Bad Event"), std::string::npos) << env.sentRaw(0);
	EXPECT_NE(env.sentRaw(0).find("Allow-Events: dialog"), std::string::npos) << env.sentRaw(0);
}

// Issue #202: a SERVICE extension is not a watchable endpoint. This machine has
// never required the watched target to be REGISTERed — an unknown extension is
// legitimately subscribable, which is how a BLF key survives the watched phone
// rebooting — so nothing but the charset gate stood between a busy-lamp key
// labelled "pbx" and a live subscription reporting dialog state for an identity
// the ENGINE originates calls as. The register beep and the hold-music preview
// would have lit somebody's lamp.
TEST(BlfSubscriptions, RejectsASubscribeAimedAtAServiceExtension)
{
	FakePbxEnv env;
	BlfSubscriptions blf(env);
	const sockaddr_in watcherAddr = FakePbxEnv::addr("192.168.1.60", 5060);

	blf.onSubscribe(subscribe("200", "pbx", "watch-svc@192.168.1.60", "Event: dialog", 3600,
		watcherAddr));

	ASSERT_EQ(env.sent.size(), 1u) << "no 202 and no NOTIFY may be minted";
	EXPECT_NE(env.sentRaw(0).find("404 Not Found"), std::string::npos) << env.sentRaw(0);

	// Not vacuous: an ordinary, equally-unregistered extension is still watchable.
	FakePbxEnv env2;
	BlfSubscriptions blf2(env2);
	blf2.onSubscribe(subscribe("200", "9999", "watch-ok@192.168.1.60", "Event: dialog", 3600,
		watcherAddr));
	ASSERT_EQ(env2.sent.size(), 2u);
	EXPECT_NE(env2.sentRaw(0).find("202 Accepted"), std::string::npos) << env2.sentRaw(0);
}

// The compact form "o:" is the Event header (RFC 6665 §8.2.1), and an Event
// header carrying an ;id= parameter still names the dialog package.
TEST(BlfSubscriptions, AcceptsCompactEventHeaderAndIgnoresParameters)
{
	FakePbxEnv env;
	BlfSubscriptions blf(env);
	const sockaddr_in watcherAddr = FakePbxEnv::addr("192.168.1.60", 5060);

	blf.onSubscribe(subscribe("200", "101", "watch-3@192.168.1.60", "o: dialog;id=7", 3600,
		watcherAddr));

	ASSERT_EQ(env.sent.size(), 2u) << env.sentRaw(0);
	EXPECT_NE(env.sentRaw(0).find("202 Accepted"), std::string::npos) << env.sentRaw(0);
}

// A SUBSCRIBE with no Event header at all must not be treated as "dialog" — and
// must not pick up the SDP origin line, which is also named "o".
TEST(BlfSubscriptions, MissingEventHeaderIsRejected)
{
	FakePbxEnv env;
	BlfSubscriptions blf(env);
	const sockaddr_in watcherAddr = FakePbxEnv::addr("192.168.1.60", 5060);

	blf.onSubscribe(subscribe("200", "101", "watch-4@192.168.1.60", "", 3600, watcherAddr));

	ASSERT_EQ(env.sent.size(), 1u);
	EXPECT_NE(env.sentRaw(0).find("Bad Event"), std::string::npos) << env.sentRaw(0);
}

// A watched extension in a connected call lights the lamp: state=confirmed.
TEST(BlfSubscriptions, ConfirmedCallOnWatchedTargetNotifiesConfirmed)
{
	FakePbxEnv env;
	BlfSubscriptions blf(env);
	const sockaddr_in watcherAddr = FakePbxEnv::addr("192.168.1.60", 5060);
	const sockaddr_in phoneAddr   = FakePbxEnv::addr("192.168.1.50", 5060);

	auto caller = std::make_shared<SipClient>("101", phoneAddr);
	auto callee = std::make_shared<SipClient>("102", phoneAddr);
	auto session = std::make_shared<Session>("call-abc", caller);
	session->setDest(callee);
	session->setState(Session::State::Connected);
	env.sessions.emplace("call-abc", session);

	blf.onSubscribe(subscribe("200", "101", "watch-5@192.168.1.60", "Event: dialog", 3600,
		watcherAddr));

	ASSERT_EQ(env.sent.size(), 2u);
	const std::string notify = env.sentRaw(1);
	EXPECT_NE(notify.find("<state>confirmed</state>"), std::string::npos) << notify;
	EXPECT_NE(notify.find("direction=\"initiator\""), std::string::npos) << notify;
}

// Issue #106: forEachSessionInvolving used to be an if/else-if chain, so a
// session whose src AND dest are the same watched extension (self-call) only
// ever reported the Caller leg — the Callee leg was silently dropped. Both
// checks must be independent so a self-call invokes the callback twice, once
// per role.
TEST(BlfSubscriptions, ForEachSessionInvolvingFiresBothRolesForSelfCall)
{
	FakePbxEnv env;
	const sockaddr_in phoneAddr = FakePbxEnv::addr("192.168.1.50", 5060);

	auto self = std::make_shared<SipClient>("101", phoneAddr);
	auto session = std::make_shared<Session>("call-self", self);
	session->setDest(self);
	env.sessions.emplace("call-self", session);

	std::vector<PbxEnv::DialogRole> rolesSeen;
	env.forEachSessionInvolving("101",
		[&](const std::string& callID, const Session&, PbxEnv::DialogRole role)
	{
		EXPECT_EQ(callID, "call-self");
		rolesSeen.push_back(role);
	});

	ASSERT_EQ(rolesSeen.size(), 2u);
	EXPECT_EQ(rolesSeen[0], PbxEnv::DialogRole::Caller);
	EXPECT_EQ(rolesSeen[1], PbxEnv::DialogRole::Callee);
}

// End-to-end through the real BlfSubscriptions::computeDialogState: with the
// bug, a ringing self-call only ever reported the Caller leg ("trying"/
// initiator); with both roles firing, the higher-ranked Callee leg ("early"/
// recipient) wins, since dest is visited after src.
TEST(BlfSubscriptions, SelfCallRingingReportsCalleeLegNotJustCaller)
{
	FakePbxEnv env;
	BlfSubscriptions blf(env);
	const sockaddr_in watcherAddr = FakePbxEnv::addr("192.168.1.60", 5060);
	const sockaddr_in phoneAddr   = FakePbxEnv::addr("192.168.1.50", 5060);

	auto self = std::make_shared<SipClient>("101", phoneAddr);
	auto session = std::make_shared<Session>("call-self", self);
	session->setDest(self);
	session->setState(Session::State::Invited);
	env.sessions.emplace("call-self", session);

	blf.onSubscribe(subscribe("200", "101", "watch-6@192.168.1.60", "Event: dialog", 3600,
		watcherAddr));

	ASSERT_EQ(env.sent.size(), 2u);
	const std::string notify = env.sentRaw(1);
	EXPECT_NE(notify.find("<state>early</state>"), std::string::npos) << notify;
	EXPECT_NE(notify.find("direction=\"recipient\""), std::string::npos) << notify;
}
