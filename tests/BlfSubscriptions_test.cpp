// Wire-level tests for the BLF/dialog-info subscription machine
// (src/SIP/BlfSubscriptions.cpp): the event-package gate, the 202 Accepted, and
// the header shape of the NOTIFY it mints inside the subscription dialog.

#include <gtest/gtest.h>

#include "BlfSubscriptions.hpp"
#include "FakePbxEnv.hpp"
#include "SipHeaderUtil.hpp"

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

// ── MWI (RFC 3842 message-summary) on the same subscription table ────────────

// A registered phone subscribing to its OWN mailbox gets a 202 and an immediate
// NOTIFY carrying the simple-message-summary body. Nothing deposited yet: "no".
TEST(BlfSubscriptions, MwiSubscribeGetsAcceptedAndAnImmediateNotifyNo)
{
	FakePbxEnv env;
	BlfSubscriptions blf(env);
	const sockaddr_in phoneAddr = FakePbxEnv::addr("192.168.1.60", 5060);
	env.registered["201"] = std::make_shared<SipClient>("201", phoneAddr);

	blf.onSubscribe(subscribe("201", "201", "mwi-1@192.168.1.60", "Event: message-summary",
		3600, phoneAddr));

	ASSERT_EQ(env.sent.size(), 2u) << env.sentRaw(0);
	EXPECT_NE(env.sentRaw(0).find("202 Accepted"), std::string::npos) << env.sentRaw(0);
	const std::string notify = env.sentRaw(1);
	EXPECT_EQ(notify.rfind("NOTIFY sip:192.168.1.60:5060", 0), 0u) << notify;
	EXPECT_NE(notify.find("Event: message-summary\r\n"), std::string::npos) << notify;
	EXPECT_NE(notify.find("Content-Type: application/simple-message-summary\r\n"),
		std::string::npos) << notify;
	EXPECT_NE(notify.find("Messages-Waiting: no\r\n"), std::string::npos) << notify;
	EXPECT_NE(notify.find("Message-Account: sip:201@"), std::string::npos) << notify;
	EXPECT_NE(notify.find("Voice-Message: 0/0 (0/0)\r\n"), std::string::npos) << notify;
	EXPECT_EQ(notify.find("dialog-info"), std::string::npos) << notify;
}

// A mailbox is private: another extension's counts are not for this phone, and
// an unregistered source gets nothing either. 403, no 202, no NOTIFY.
TEST(BlfSubscriptions, MwiRefusesAnotherExtensionsMailboxAndUnregisteredPhones)
{
	FakePbxEnv env;
	BlfSubscriptions blf(env);
	const sockaddr_in phoneAddr = FakePbxEnv::addr("192.168.1.60", 5060);
	env.registered["201"] = std::make_shared<SipClient>("201", phoneAddr);

	blf.onSubscribe(subscribe("201", "202", "mwi-2@192.168.1.60", "Event: message-summary",
		3600, phoneAddr));
	ASSERT_EQ(env.sent.size(), 1u);
	EXPECT_NE(env.sentRaw(0).find("403 Forbidden"), std::string::npos) << env.sentRaw(0);

	env.sent.clear();
	blf.onSubscribe(subscribe("203", "203", "mwi-3@192.168.1.60", "Event: message-summary",
		3600, phoneAddr));
	ASSERT_EQ(env.sent.size(), 1u);
	EXPECT_NE(env.sentRaw(0).find("403 Forbidden"), std::string::npos) << env.sentRaw(0);
}

// Positive control for the gate: an unknown package is still 489, and the
// Allow-Events it advertises now names both packages this table serves.
TEST(BlfSubscriptions, UnknownPackageStill489sAndAdvertisesMessageSummary)
{
	FakePbxEnv env;
	BlfSubscriptions blf(env);
	const sockaddr_in phoneAddr = FakePbxEnv::addr("192.168.1.60", 5060);
	env.registered["201"] = std::make_shared<SipClient>("201", phoneAddr);

	blf.onSubscribe(subscribe("201", "201", "mwi-4@192.168.1.60", "Event: presence", 3600,
		phoneAddr));

	ASSERT_EQ(env.sent.size(), 1u);
	EXPECT_NE(env.sentRaw(0).find("489 Bad Event"), std::string::npos) << env.sentRaw(0);
	EXPECT_NE(env.sentRaw(0).find("Allow-Events: dialog, message-summary"), std::string::npos)
		<< env.sentRaw(0);
}

// ── MWI review fixes (#757) ──────────────────────────────────────────────────
namespace
{
	// A SUBSCRIBE carrying explicit dialog tags: fromTag is the watcher's, toTag
	// ours from the 202 ("" for an initial SUBSCRIBE).
	std::shared_ptr<SipMessage> mwiSubscribe(const std::string& ext, const std::string& callId,
		const std::string& eventHdr, const std::string& fromTag, const std::string& toTag,
		int expires, const sockaddr_in& src)
	{
		std::string raw =
			"SUBSCRIBE sip:" + ext + "@192.168.1.10 SIP/2.0\r\n"
			"Via: SIP/2.0/UDP 192.168.1.99:5060;branch=z9hG4bKmwirev" + std::to_string(expires) + "\r\n"
			"From: <sip:" + ext + "@192.168.1.10>;tag=" + fromTag + "\r\n"
			"To: <sip:" + ext + "@192.168.1.10>" + (toTag.empty() ? "" : ";tag=" + toTag) + "\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 2 SUBSCRIBE\r\n" + eventHdr + "\r\n"
			"Expires: " + std::to_string(expires) + "\r\n"
			"Content-Length: 0\r\n\r\n";
		return std::make_shared<SipMessage>(raw, src);
	}

	std::string toTagOf202(const FakePbxEnv& env)
	{
		for (const auto& s : env.sent)
		{
			if (s.raw.find("202 Accepted") == std::string::npos) continue;
			size_t p = s.raw.find("\r\nTo: ");
			if (p == std::string::npos) return {};
			return siphdr::tagOf(s.raw.substr(p + 2, s.raw.find("\r\n", p + 2) - (p + 2)));
		}
		return {};
	}

	bool sameIp(const sockaddr_in& a, const sockaddr_in& b)
	{
		return a.sin_addr.s_addr == b.sin_addr.s_addr;
	}
}

// The source-IP half of the ownership gate: the right extension in From/To, but
// sent from a host other than the one that extension registered from.
TEST(BlfSubscriptions, MwiRefusesAnInitialSubscribeFromAnotherIp)
{
	FakePbxEnv env;
	BlfSubscriptions blf(env);
	env.registered["201"] = std::make_shared<SipClient>("201", FakePbxEnv::addr("192.168.1.60", 5060));

	blf.onSubscribe(mwiSubscribe("201", "mwi-ip@x", "Event: message-summary", "w1", "", 3600,
		FakePbxEnv::addr("192.168.1.99", 5060)));

	ASSERT_EQ(env.sent.size(), 1u) << env.sentRaw(0);
	EXPECT_NE(env.sentRaw(0).find("403 Forbidden"), std::string::npos) << env.sentRaw(0);
}

// A dialog-package SUBSCRIBE reusing an MWI subscription's Call-ID is not that
// subscription: it must not move the MWI slot's NOTIFY address or be handed a
// message-summary NOTIFY.
TEST(BlfSubscriptions, DialogSubscribeReusingAnMwiCallIdCannotHijackTheMailbox)
{
	FakePbxEnv env;
	BlfSubscriptions blf(env);
	const sockaddr_in owner = FakePbxEnv::addr("192.168.1.60", 5060);
	const sockaddr_in other = FakePbxEnv::addr("192.168.1.99", 5060);
	env.registered["201"] = std::make_shared<SipClient>("201", owner);

	blf.onSubscribe(mwiSubscribe("201", "shared-cid", "Event: message-summary", "w1", "", 3600, owner));
	ASSERT_EQ(env.sent.size(), 2u);
	env.sent.clear();

	blf.onSubscribe(mwiSubscribe("201", "shared-cid", "Event: dialog", "evil", "", 3600, other));
	for (const auto& s : env.sent)
	{
		if (!sameIp(s.to, other)) continue;
		EXPECT_EQ(s.raw.find("message-summary"), std::string::npos)
			<< "the other host got a mailbox NOTIFY:\n" << s.raw;
	}

	env.sent.clear();
	blf.mwiDeposit("201");
	blf.refresh();
	bool ownerNotified = false;
	for (const auto& s : env.sent)
	{
		const bool mwi = s.raw.find("Event: message-summary") != std::string::npos;
		if (mwi && sameIp(s.to, owner)) ownerNotified = true;
		EXPECT_FALSE(mwi && sameIp(s.to, other)) << s.raw;
	}
	EXPECT_TRUE(ownerNotified) << "the deposit NOTIFY must still reach the owner";
}

// An in-dialog refresh or unsubscribe (Call-ID + both tags) from the owner is
// honoured after its IP changed; the same Call-ID without our To-tag is not.
TEST(BlfSubscriptions, MwiInDialogRefreshAndUnsubscribeSurviveAnIpChange)
{
	FakePbxEnv env;
	BlfSubscriptions blf(env);
	const sockaddr_in oldIp = FakePbxEnv::addr("192.168.1.60", 5060);
	const sockaddr_in newIp = FakePbxEnv::addr("192.168.1.70", 5060);
	env.registered["201"] = std::make_shared<SipClient>("201", oldIp);

	blf.onSubscribe(mwiSubscribe("201", "roam-cid", "Event: message-summary", "w1", "", 3600, oldIp));
	const std::string ourTag = toTagOf202(env);
	ASSERT_FALSE(ourTag.empty());

	// Not in-dialog (no To-tag) from the new IP: still the initial-SUBSCRIBE gate.
	env.sent.clear();
	blf.onSubscribe(mwiSubscribe("201", "roam-cid", "Event: message-summary", "w1", "", 3600, newIp));
	ASSERT_EQ(env.sent.size(), 1u);
	EXPECT_NE(env.sentRaw(0).find("403 Forbidden"), std::string::npos) << env.sentRaw(0);

	// In-dialog refresh from the new IP: 202 + NOTIFY, and the NOTIFY goes there.
	env.sent.clear();
	blf.onSubscribe(mwiSubscribe("201", "roam-cid", "Event: message-summary", "w1", ourTag, 3600, newIp));
	ASSERT_EQ(env.sent.size(), 2u) << env.sentRaw(0);
	EXPECT_NE(env.sentRaw(0).find("202 Accepted"), std::string::npos) << env.sentRaw(0);
	EXPECT_TRUE(sameIp(env.sent[1].to, newIp)) << env.sentRaw(1);

	// In-dialog unsubscribe from the new IP: terminated, and no NOTIFY after it.
	env.sent.clear();
	blf.onSubscribe(mwiSubscribe("201", "roam-cid", "Event: message-summary", "w1", ourTag, 0, newIp));
	ASSERT_EQ(env.sent.size(), 2u) << env.sentRaw(0);
	EXPECT_NE(env.sentRaw(1).find("Subscription-State: terminated"), std::string::npos) << env.sentRaw(1);
	env.sent.clear();
	blf.mwiDeposit("201");
	blf.refresh();
	EXPECT_TRUE(env.sent.empty()) << env.sentRaw(0);
}
