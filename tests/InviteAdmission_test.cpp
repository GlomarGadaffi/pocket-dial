// InviteAdmission_test.cpp — the two gates onInvite grew ahead of routing:
//
//   1. Codec gate: an offer with no audio codec this PBX relays gets 488 Not
//      Acceptable Here before a session is allocated; an offer we can carry is
//      forwarded with its preference order intact (no more blind "0 8 101").
//   2. Secure-mode INVITE digest challenge (drawbridge #125): registration auth
//      alone left call setup open to anyone who could reach UDP/5060. In Secure
//      mode an INVITE without credentials is answered 401 + WWW-Authenticate; the
//      credentialed retry (same Call-ID, CSeq+1) is admitted; bad credentials get
//      403. Open mode is unchanged.
//
// Drives a real RequestsHandler through handle(), asserting on the bytes it
// sends, in the style of Invite777SessionPool_test.cpp.

#include <gtest/gtest.h>

#include <string>
#include <utility>
#include <vector>

#include "RequestsHandler.hpp"
#include "SipDigest.hpp"
#include "SipSecretStore.hpp"

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#else
#include <arpa/inet.h>
#endif

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

	const std::string kPcmuOffer =
		"m=audio 10000 RTP/AVP 0 101\r\n"
		"a=rtpmap:0 PCMU/8000\r\n"
		"a=rtpmap:101 telephone-event/8000\r\n";

	std::shared_ptr<SipMessage> makeInvite(const std::string& callId, int cseq,
	                                        const std::string& mediaLines,
	                                        const std::string& extraHeaders = "")
	{
		const std::string srcIp = "192.168.7.50";
		std::string body =
			"v=0\r\n"
			"o=- 0 0 IN IP4 " + srcIp + "\r\n"
			"s=-\r\n"
			"c=IN IP4 " + srcIp + "\r\n"
			"t=0 0\r\n" + mediaLines + "a=sendrecv\r\n";
		std::string raw =
			"INVITE sip:600@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + srcIp + ":5060;branch=z9hG4bKi" + callId + std::to_string(cseq) + "\r\n"
			"From: <sip:500@server>;tag=ft" + callId + "\r\n"
			"To: <sip:600@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: " + std::to_string(cseq) + " INVITE\r\n"
			"Max-Forwards: 70\r\n"
			"Contact: <sip:500@" + srcIp + ":5060>\r\n" + extraHeaders +
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		return RequestsHandler::getMessageFromPool(raw, addrFor(srcIp));
	}

	bool anySentContains(const Sent& sent, const std::string& needle)
	{
		for (const auto& [addr, msg] : sent)
		{
			if (msg && msg->toString().find(needle) != std::string::npos) return true;
		}
		return false;
	}

	std::string firstSentContaining(const Sent& sent, const std::string& needle)
	{
		for (const auto& [addr, msg] : sent)
		{
			std::string raw = msg ? msg->toString() : std::string{};
			if (raw.find(needle) != std::string::npos) return raw;
		}
		return {};
	}

	std::string paramOf(const std::string& raw, const std::string& key)
	{
		size_t p = raw.find(key + "=\"");
		if (p == std::string::npos) return {};
		p += key.size() + 2;
		size_t e = raw.find('"', p);
		return raw.substr(p, e - p);
	}

	struct Harness
	{
		Sent sent;
		RequestsHandler handler;
		Harness() : handler("192.168.7.1", 5060,
			[this](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
				sent.emplace_back(addr, std::move(msg));
			})
		{
			handler.handle(makeRegister("500", "192.168.7.50"));
			handler.handle(makeRegister("600", "192.168.7.60"));
			sent.clear();
		}
	};
}

namespace
{
	// An INVITE naming `fromExt` as its caller, sent from `srcIp` (#497).
	std::shared_ptr<SipMessage> makeInviteAs(const std::string& fromExt, const std::string& srcIp,
	                                          const std::string& callId)
	{
		std::string body =
			"v=0\r\no=- 0 0 IN IP4 " + srcIp + "\r\ns=-\r\nc=IN IP4 " + srcIp + "\r\nt=0 0\r\n" +
			kPcmuOffer + "a=sendrecv\r\n";
		std::string raw =
			"INVITE sip:600@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + srcIp + ":5060;branch=z9hG4bKb" + callId + "\r\n"
			"From: <sip:" + fromExt + "@server>;tag=fb" + callId + "\r\n"
			"To: <sip:600@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Max-Forwards: 70\r\n"
			"Contact: <sip:" + fromExt + "@" + srcIp + ":5060>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		return RequestsHandler::getMessageFromPool(raw, addrFor(srcIp));
	}
}

TEST(InviteAdmission, ACallFromAnotherAddressThanTheCallerRegisteredFromIsRefused)
{
	// #497: 500 registered from .50. The same From, sent from any other host, is
	// refused -- it must not be forked, and must not reach dial plan or trunk.
	Harness h;
	h.handler.handle(makeInviteAs("500", "192.168.7.99", "spoof"));
	EXPECT_TRUE(anySentContains(h.sent, "SIP/2.0 403 Caller Not Registered From This Address"));
	EXPECT_FALSE(anySentContains(h.sent, "INVITE sip:600@")) << "a spoofed caller must not ring anyone";
}

TEST(InviteAdmission, ACallFromTheCallersRegisteredAddressIsAdmitted)
{
	// The bound case, through the same builder: only the source differs above.
	Harness h;
	h.handler.handle(makeInviteAs("500", "192.168.7.50", "bound"));
	EXPECT_FALSE(anySentContains(h.sent, "Caller Not Registered From This Address"));
	EXPECT_TRUE(anySentContains(h.sent, "INVITE sip:600@"));
}

namespace
{
	// A REGISTER for `ext` from ip:port. Its own branch and CSeq, so the server
	// transaction layer treats it as a new request, not a retransmission of the
	// Harness's registration (#503 tests).
	std::shared_ptr<SipMessage> makeRegisterFrom(const std::string& ext, const std::string& ip,
	                                              uint16_t port, const std::string& tag)
	{
		const std::string hp = ip + ":" + std::to_string(port);
		std::string raw =
			"REGISTER sip:server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + hp + ";branch=z9hG4bKrr" + tag + "\r\n"
			"From: <sip:" + ext + "@server>;tag=rr" + tag + "\r\n"
			"To: <sip:" + ext + "@server>\r\n"
			"Call-ID: rereg-" + tag + "\r\n"
			"CSeq: 2 REGISTER\r\n"
			"Contact: <sip:" + ext + "@" + hp + ">;expires=3600\r\n"
			"Content-Length: 0\r\n\r\n";
		sockaddr_in s = addrFor(ip);
		s.sin_port = htons(port);
		return RequestsHandler::getMessageFromPool(raw, s);
	}
}

TEST(InviteAdmission, TheBindingIsPortAgnostic)
{
	// BigDog's #503 review: ext 113 on .244 registers from .204:5062; a phone may
	// place calls from another ephemeral port. Same IP, different port: admitted.
	Harness h;
	h.handler.handle(makeRegisterFrom("500", "192.168.7.50", 5062, "port"));
	h.sent.clear();
	h.handler.handle(makeInviteAs("500", "192.168.7.50", "port-invite"));   // from :5060
	EXPECT_FALSE(anySentContains(h.sent, "Caller Not Registered From This Address"));
	EXPECT_TRUE(anySentContains(h.sent, "INVITE sip:600@"));
}

TEST(InviteAdmission, TheBindingFollowsTheLatestRegister)
{
	// A DHCP/NAT rebind heals on the phone's next REGISTER: the new address is
	// admitted, the old one is now the stranger.
	Harness h;
	const uint64_t refusedBefore = h.handler.getUnboundCallerRefusals();
	h.handler.handle(makeRegisterFrom("500", "192.168.7.51", 5060, "rebind"));
	h.sent.clear();
	h.handler.handle(makeInviteAs("500", "192.168.7.51", "rebind-new"));
	EXPECT_TRUE(anySentContains(h.sent, "INVITE sip:600@")) << "the new address places calls";
	h.sent.clear();
	h.handler.handle(makeInviteAs("500", "192.168.7.50", "rebind-old"));
	EXPECT_TRUE(anySentContains(h.sent, "SIP/2.0 403 Caller Not Registered From This Address"));
	EXPECT_FALSE(anySentContains(h.sent, "INVITE sip:600@"));
	EXPECT_EQ(h.handler.getUnboundCallerRefusals(), refusedBefore + 1) << "every refusal is counted";
}

TEST(InviteAdmission, InSecureModeASpoofedSourceGets403NotAChallenge)
{
	// Ordering (BigDog's #503 review): the binding check runs BEFORE the Secure
	// challenge, so a spoofer never receives a nonce to work with.
	Harness h;
	ASSERT_TRUE(SipSecretStore::setSecret("500", "s3cret"));
	h.handler.setRegistrarMode(RequestsHandler::RegistrarMode::Secure);
	h.handler.handle(makeInviteAs("500", "192.168.7.99", "sec-spoof"));
	EXPECT_TRUE(anySentContains(h.sent, "SIP/2.0 403 Caller Not Registered From This Address"));
	EXPECT_FALSE(anySentContains(h.sent, "401 Unauthorized"));
	h.handler.setRegistrarMode(RequestsHandler::RegistrarMode::Learn);
	SipSecretStore::clearSecret("500");
}

TEST(InviteAdmission, OfferWithNoRelayableAudioCodecGets488BeforeAnySession)
{
	Harness h;
	h.handler.handle(makeInvite("opus-only", 1,
		"m=audio 10000 RTP/AVP 96 101\r\n"
		"a=rtpmap:96 opus/48000/2\r\n"
		"a=rtpmap:101 telephone-event/8000\r\n"));

	EXPECT_TRUE(anySentContains(h.sent, "SIP/2.0 488 Not Acceptable Here"));
	EXPECT_FALSE(anySentContains(h.sent, "INVITE sip:600@")) << "must not be forwarded";
	EXPECT_FALSE(anySentContains(h.sent, "SIP/2.0 200 OK"));
	EXPECT_FALSE(h.handler.getSession("Call-ID: opus-only").has_value())
		<< "488 is answered before allocateSession()";
}

TEST(InviteAdmission, WidebandOfferIsForwardedWithPreferenceOrderIntact)
{
	Harness h;
	h.handler.handle(makeInvite("wb", 1,
		"m=audio 10000 RTP/AVP 9 0 101\r\n"
		"a=rtpmap:9 G722/8000\r\n"
		"a=rtpmap:0 PCMU/8000\r\n"
		"a=rtpmap:101 telephone-event/8000\r\n"));

	const std::string fork = firstSentContaining(h.sent, "INVITE sip:600@");
	ASSERT_FALSE(fork.empty()) << "the INVITE must be forked to 600";
	EXPECT_NE(fork.find("m=audio 10000 RTP/AVP 9 0 101\r\n"), std::string::npos)
		<< "G.722-first order must reach the callee; got:\n" << fork;
	EXPECT_NE(fork.find("a=rtpmap:9 G722/8000"), std::string::npos);
	EXPECT_EQ(fork.find("RTP/AVP 0 8 101"), std::string::npos) << "no blind rewrite";
}

TEST(InviteAdmission, LearnModeNeverChallengesAnInvite)
{
	// Learn is the default and the floor now that open is retired (#500).
	Harness h;
	ASSERT_EQ(h.handler.getRegistrarMode(), RequestsHandler::RegistrarMode::Learn);
	h.handler.handle(makeInvite("learn", 1, kPcmuOffer));
	EXPECT_FALSE(anySentContains(h.sent, "401 Unauthorized"));
	EXPECT_TRUE(anySentContains(h.sent, "INVITE sip:600@"));
}

TEST(InviteAdmission, SecureModeChallengesInviteThenAdmitsCredentialedRetry)
{
	Harness h;
	ASSERT_TRUE(SipSecretStore::setSecret("500", "s3cret"));
	h.handler.setRegistrarMode(RequestsHandler::RegistrarMode::Secure);

	// 1. Bare INVITE -> 401 with a Digest challenge, nothing forwarded.
	h.handler.handle(makeInvite("sec", 1, kPcmuOffer));
	const std::string challenge = firstSentContaining(h.sent, "SIP/2.0 401 Unauthorized");
	ASSERT_FALSE(challenge.empty()) << "Secure mode must challenge the INVITE";
	EXPECT_NE(challenge.find("WWW-Authenticate: Digest realm=\"pocketdial\""), std::string::npos);
	EXPECT_FALSE(anySentContains(h.sent, "INVITE sip:600@"));
	EXPECT_FALSE(h.handler.getSession("Call-ID: sec").has_value());

	// 2. Retry with credentials computed exactly as a phone (or tincan-core's
	//    digest client) would: same Call-ID, CSeq+1, response over method INVITE
	//    and the Request-URI.
	const std::string nonce = paramOf(challenge, "nonce");
	ASSERT_FALSE(nonce.empty());
	const std::string ha1 = SipDigest::computeHa1("500", SipSecretStore::kRealm, "s3cret");
	const std::string response = SipDigest::computeResponse(
		ha1, "INVITE", "sip:600@server", nonce, "00000001", "0a4f113b", "auth");
	const std::string authz =
		"Authorization: Digest username=\"500\", realm=\"pocketdial\", nonce=\"" + nonce +
		"\", uri=\"sip:600@server\", response=\"" + response +
		"\", algorithm=MD5, qop=auth, nc=00000001, cnonce=\"0a4f113b\"\r\n";

	h.sent.clear();
	h.handler.handle(makeInvite("sec", 2, kPcmuOffer, authz));
	EXPECT_FALSE(anySentContains(h.sent, "401 Unauthorized")) << "valid credentials must not be re-challenged";
	// Match the status LINE, not a bare "403" (issue #136). anySentContains() is a
	// plain substring search over the whole message, and the INVITE forked to 600
	// echoes this request's Authorization header verbatim -- 64 characters of digest
	// nonce and MD5 response hex. Those 62 three-character windows hit "403" roughly
	// 1.5% of the time (measured 3/400 fresh processes), which is exactly the
	// order-dependent-looking intermittent failure #136 recorded: the credentials
	// were accepted and the fork went out, but a random hex triple spelled the code
	// this line was watching for. The sibling assertion at the bottom of this test
	// already uses the full "SIP/2.0 403 Bad Credentials" form.
	EXPECT_FALSE(anySentContains(h.sent, "SIP/2.0 403"))
		<< "valid credentials must not be rejected";
	EXPECT_TRUE(anySentContains(h.sent, "INVITE sip:600@")) << "admitted INVITE is forked to the callee";

	// 3. Wrong password -> 403, not a loop of challenges.
	const std::string badResp = SipDigest::computeResponse(
		SipDigest::computeHa1("500", SipSecretStore::kRealm, "wrong"),
		"INVITE", "sip:600@server", nonce, "00000001", "0a4f113b", "auth");
	const std::string badAuthz =
		"Authorization: Digest username=\"500\", realm=\"pocketdial\", nonce=\"" + nonce +
		"\", uri=\"sip:600@server\", response=\"" + badResp +
		"\", algorithm=MD5, qop=auth, nc=00000001, cnonce=\"0a4f113b\"\r\n";
	h.sent.clear();
	h.handler.handle(makeInvite("sec-bad", 1, kPcmuOffer, badAuthz));
	EXPECT_TRUE(anySentContains(h.sent, "SIP/2.0 403 Bad Credentials"));
	EXPECT_FALSE(anySentContains(h.sent, "INVITE sip:600@"));

	h.handler.setRegistrarMode(RequestsHandler::RegistrarMode::Learn);
}

// #505 (#497 layer 2): in Learn mode, a device an admin promoted to Secured is
// digest-enforced on REGISTER; its INVITEs now prove the same secret, exactly
// as in Secure mode. Otherwise a spoofed INVITE naming it places calls as it.
namespace
{
	// Clears a test secret on EVERY exit, including an early ASSERT return, so it
	// cannot leak into later tests (BigDog's #512 review).
	struct SecretGuard
	{
		std::string ext;
		~SecretGuard() { SipSecretStore::clearSecret(ext); }
	};
}

TEST(InviteAdmission, LearnModeChallengesAnInviteFromASecuredDevice)
{
	Harness h;
	SecretGuard guard{"500"};
	ASSERT_TRUE(SipSecretStore::setSecret("500", "s3cret"));
	h.handler.setRegistrarMode(RequestsHandler::RegistrarMode::Learn);
	h.handler.adoptDeviceForTest("0200000000aa", "500", Registrar::DeviceState::Secured);

	h.handler.handle(makeInvite("lsec", 1, kPcmuOffer));
	const std::string challenge = firstSentContaining(h.sent, "SIP/2.0 401 Unauthorized");
	ASSERT_FALSE(challenge.empty()) << "a Secured device's INVITE must be challenged in Learn mode";
	EXPECT_FALSE(anySentContains(h.sent, "INVITE sip:600@"));

	const std::string nonce = paramOf(challenge, "nonce");
	ASSERT_FALSE(nonce.empty());
	const std::string ha1 = SipDigest::computeHa1("500", SipSecretStore::kRealm, "s3cret");
	const std::string response = SipDigest::computeResponse(
		ha1, "INVITE", "sip:600@server", nonce, "00000001", "0a4f113b", "auth");
	const std::string authz =
		"Authorization: Digest username=\"500\", realm=\"pocketdial\", nonce=\"" + nonce +
		"\", uri=\"sip:600@server\", response=\"" + response +
		"\", algorithm=MD5, qop=auth, nc=00000001, cnonce=\"0a4f113b\"\r\n";
	h.sent.clear();
	h.handler.handle(makeInvite("lsec", 2, kPcmuOffer, authz));
	EXPECT_FALSE(anySentContains(h.sent, "401 Unauthorized"));
	EXPECT_TRUE(anySentContains(h.sent, "INVITE sip:600@")) << "the credentialed retry is admitted";
}

TEST(InviteAdmission, LearnModeRefusesASecuredDevicesInviteWithWrongCredentials)
{
	Harness h;
	SecretGuard guard{"500"};
	ASSERT_TRUE(SipSecretStore::setSecret("500", "s3cret"));
	h.handler.setRegistrarMode(RequestsHandler::RegistrarMode::Learn);
	h.handler.adoptDeviceForTest("0200000000aa", "500", Registrar::DeviceState::Secured);
	h.handler.handle(makeInvite("lbad", 1, kPcmuOffer));
	const std::string nonce = paramOf(firstSentContaining(h.sent, "SIP/2.0 401 Unauthorized"), "nonce");
	ASSERT_FALSE(nonce.empty());
	const std::string ha1 = SipDigest::computeHa1("500", SipSecretStore::kRealm, "not-the-secret");
	const std::string response = SipDigest::computeResponse(
		ha1, "INVITE", "sip:600@server", nonce, "00000001", "0a4f113b", "auth");
	const std::string authz =
		"Authorization: Digest username=\"500\", realm=\"pocketdial\", nonce=\"" + nonce +
		"\", uri=\"sip:600@server\", response=\"" + response +
		"\", algorithm=MD5, qop=auth, nc=00000001, cnonce=\"0a4f113b\"\r\n";
	h.sent.clear();
	h.handler.handle(makeInvite("lbad", 2, kPcmuOffer, authz));
	EXPECT_TRUE(anySentContains(h.sent, "SIP/2.0 403 Bad Credentials"));
	EXPECT_FALSE(anySentContains(h.sent, "INVITE sip:600@"));
}

TEST(InviteAdmission, LearnModeStillAdmitsAnUnsecuredCallerWithoutAChallenge)
{
	// #505 must not reach Learned (TOFU) extensions: they have no secret. Another
	// extension (600) IS Secured, so a mutation that challenges whenever ANY device
	// is Secured, ignoring the caller, goes red here (BigDog's #512 review).
	Harness h;
	h.handler.setRegistrarMode(RequestsHandler::RegistrarMode::Learn);
	h.handler.adoptDeviceForTest("0200000000bb", "600", Registrar::DeviceState::Secured);
	// The caller itself is an ADOPTED Learned device, so dropping the Secured
	// state test from isExtensionSecured() ("any adopted device") goes red too
	// (Crew's #512 review, finding 4).
	h.handler.adoptDeviceForTest("0200000000ab", "500", Registrar::DeviceState::Learned);
	h.handler.handle(makeInvite("lplain", 1, kPcmuOffer));
	EXPECT_FALSE(anySentContains(h.sent, "401 Unauthorized"));
	EXPECT_TRUE(anySentContains(h.sent, "INVITE sip:600@"));
}

namespace
{
	// A credentialed INVITE for 500, answering the 401 the bare one drew. The
	// digest covers `digestUri`, which a replay may point somewhere else.
	std::string credentialsFor(const std::string& challenge, const std::string& digestUri)
	{
		const std::string nonce = paramOf(challenge, "nonce");
		const std::string ha1 = SipDigest::computeHa1("500", SipSecretStore::kRealm, "s3cret");
		const std::string response = SipDigest::computeResponse(
			ha1, "INVITE", digestUri, nonce, "00000001", "0a4f113b", "auth");
		return "Authorization: Digest username=\"500\", realm=\"pocketdial\", nonce=\"" + nonce +
			"\", uri=\"" + digestUri + "\", response=\"" + response +
			"\", algorithm=MD5, qop=auth, nc=00000001, cnonce=\"0a4f113b\"\r\n";
	}
}

TEST(InviteAdmission, CredentialsForAnotherRequestUriAreRefused)
{
	// #512 review (Crew, MEDIUM): the hash covers the Authorization's uri, not
	// the Request-URI the call is routed on. A valid digest over sip:700@server
	// must not place a call to 600.
	Harness h;
	SecretGuard guard{"500"};
	ASSERT_TRUE(SipSecretStore::setSecret("500", "s3cret"));
	h.handler.setRegistrarMode(RequestsHandler::RegistrarMode::Secure);

	h.handler.handle(makeInvite("xuri", 1, kPcmuOffer));
	const std::string challenge = firstSentContaining(h.sent, "SIP/2.0 401 Unauthorized");
	ASSERT_FALSE(challenge.empty());

	h.sent.clear();
	h.handler.handle(makeInvite("xuri", 2, kPcmuOffer, credentialsFor(challenge, "sip:700@server")));
	EXPECT_TRUE(anySentContains(h.sent, "SIP/2.0 403 Credentials Not For This Request"));
	EXPECT_FALSE(anySentContains(h.sent, "INVITE sip:600@"))
		<< "a digest over another URI must not authorise this call";
}

TEST(InviteAdmission, ACredentialedInviteWhoseToDisagreesWithTheRequestUriIsRefused)
{
	// #512 review: the digest binds the Request-URI, but routing reads the To
	// user. A replay that keeps the Request-URI and rewrites only To must not
	// reach the new destination.
	Harness h;
	SecretGuard guard{"500"};
	ASSERT_TRUE(SipSecretStore::setSecret("500", "s3cret"));
	h.handler.setRegistrarMode(RequestsHandler::RegistrarMode::Secure);

	h.handler.handle(makeInvite("xto", 1, kPcmuOffer));
	const std::string challenge = firstSentContaining(h.sent, "SIP/2.0 401 Unauthorized");
	ASSERT_FALSE(challenge.empty());

	h.sent.clear();
	auto invite = makeInvite("xto", 2, kPcmuOffer, credentialsFor(challenge, "sip:600@server"));
	ASSERT_TRUE(invite);
	invite->setTo("To: <sip:700@server>");
	h.handler.handle(invite);
	EXPECT_TRUE(anySentContains(h.sent, "SIP/2.0 403 Request-URI And To Disagree"));
	EXPECT_FALSE(anySentContains(h.sent, "INVITE sip:700@"));
	EXPECT_FALSE(anySentContains(h.sent, "INVITE sip:600@"));
}

TEST(InviteAdmission, TheCalleeNeverSeesTheCallersCredentials)
{
	// #512 review (Crew, MEDIUM): relayed verbatim, the Authorization let the
	// callee replay the caller's credentials at this PBX for the nonce's life.
	Harness h;
	SecretGuard guard{"500"};
	ASSERT_TRUE(SipSecretStore::setSecret("500", "s3cret"));
	h.handler.setRegistrarMode(RequestsHandler::RegistrarMode::Secure);

	h.handler.handle(makeInvite("strip", 1, kPcmuOffer));
	const std::string challenge = firstSentContaining(h.sent, "SIP/2.0 401 Unauthorized");
	ASSERT_FALSE(challenge.empty());

	h.sent.clear();
	h.handler.handle(makeInvite("strip", 2, kPcmuOffer,
		credentialsFor(challenge, "sip:600@server") +
		"Proxy-Authorization: Digest username=\"500\", realm=\"x\", nonce=\"n\", uri=\"sip:600@server\", response=\"0\"\r\n"));
	const std::string fork = firstSentContaining(h.sent, "INVITE sip:600@");
	ASSERT_FALSE(fork.empty()) << "the credentialed INVITE is admitted and forked";
	EXPECT_EQ(fork.find("Authorization:"), std::string::npos)
		<< "neither Authorization nor Proxy-Authorization may reach the callee:\n" << fork;
	for (const auto& entry : h.sent)
	{
		const std::string raw = entry.second->toString();
		EXPECT_EQ(raw.find("Authorization:"), std::string::npos)
			<< "no message this PBX sends may carry the caller's credentials:\n" << raw;
	}
}

// ── #560: in-dialog relays never carry the INVITE's credential ───────────────
namespace
{
	// Secure mode, a challenged-then-admitted call 500 -> 600 on Call-ID `id`.
	// Returns the credential line the admitted INVITE carried.
	std::string admitCredentialedCall(Harness& h, const std::string& id)
	{
		h.handler.handle(makeInvite(id, 1, kPcmuOffer));
		const std::string challenge = firstSentContaining(h.sent, "SIP/2.0 401 Unauthorized");
		const std::string creds = credentialsFor(challenge, "sip:600@server");
		h.handler.handle(makeInvite(id, 2, kPcmuOffer, creds));
		return creds;
	}

	// Appended to every in-dialog relay test's credential, so the
	// find("Authorization:") checks pin the Proxy-Authorization strip too.
	const std::string kProxyAuth =
		"Proxy-Authorization: Digest username=\"500\", realm=\"pocketdial\", nonce=\"n560\", "
		"uri=\"sip:600@server\", response=\"00000000000000000000000000000000\"\r\n";

	std::string lastSentTo600Starting(const Sent& sent, const std::string& start)
	{
		std::string out;
		for (const auto& [addr, msg] : sent)
		{
			const std::string raw = msg ? msg->toString() : std::string{};
			if (addr.sin_addr.s_addr == inet_addr("192.168.7.60") && raw.rfind(start, 0) == 0) out = raw;
		}
		return out;
	}
}

TEST(InviteAdmission, TheRelayedAckCarriesNoCredential)
{
	// RFC 3261 §13.2.2.4 has the caller repeat the INVITE's credentials on the
	// 2xx ACK; relayed verbatim (onAck -> endHandle) the callee got them anyway.
	Harness h;
	SecretGuard guard{"500"};
	ASSERT_TRUE(SipSecretStore::setSecret("500", "s3cret"));
	h.handler.setRegistrarMode(RequestsHandler::RegistrarMode::Secure);
	const std::string creds = admitCredentialedCall(h, "ack560");
	ASSERT_FALSE(firstSentContaining(h.sent, "INVITE sip:600@").empty());

	auto ack = makeInvite("ack560", 2, kPcmuOffer, creds + kProxyAuth);
	ack->setHeader("ACK sip:600@server SIP/2.0");
	ack->setCSeq("CSeq: 2 ACK");
	ack->setTo("To: <sip:600@server>;tag=callee560");
	ack->clearBody();
	h.sent.clear();
	h.handler.handle(ack);

	const std::string relayed = lastSentTo600Starting(h.sent, "ACK ");
	ASSERT_FALSE(relayed.empty()) << "the ACK is relayed to the callee";
	EXPECT_EQ(relayed.find("Authorization:"), std::string::npos) << relayed;
}

TEST(InviteAdmission, ARelayedReinviteCarriesNoCredential)
{
	Harness h;
	SecretGuard guard{"500"};
	ASSERT_TRUE(SipSecretStore::setSecret("500", "s3cret"));
	h.handler.setRegistrarMode(RequestsHandler::RegistrarMode::Secure);
	const std::string creds = admitCredentialedCall(h, "re560");
	ASSERT_FALSE(firstSentContaining(h.sent, "INVITE sip:600@").empty());

	auto reinvite = makeInvite("re560", 3, kPcmuOffer, creds + kProxyAuth);
	reinvite->setTo("To: <sip:600@server>;tag=callee560");
	h.sent.clear();
	h.handler.handle(reinvite);

	const std::string relayed = lastSentTo600Starting(h.sent, "INVITE ");
	ASSERT_FALSE(relayed.empty()) << "the re-INVITE is relayed to the callee";
	EXPECT_EQ(relayed.find("Authorization:"), std::string::npos) << relayed;
}

TEST(InviteAdmission, ARelayedUpdateCarriesNoCredential)
{
	// #560: onUpdate() relays an in-dialog UPDATE to the peer; a phone that
	// resends its INVITE credential there must not hand it to the callee.
	Harness h;
	SecretGuard guard{"500"};
	ASSERT_TRUE(SipSecretStore::setSecret("500", "s3cret"));
	h.handler.setRegistrarMode(RequestsHandler::RegistrarMode::Secure);
	const std::string creds = admitCredentialedCall(h, "up560");
	ASSERT_FALSE(firstSentContaining(h.sent, "INVITE sip:600@").empty());

	auto update = makeInvite("up560", 3, kPcmuOffer, creds + kProxyAuth);
	update->setHeader("UPDATE sip:600@server SIP/2.0");
	update->setCSeq("CSeq: 3 UPDATE");
	update->setTo("To: <sip:600@server>;tag=callee560");
	h.sent.clear();
	h.handler.handle(update);

	const std::string relayed = lastSentTo600Starting(h.sent, "UPDATE ");
	ASSERT_FALSE(relayed.empty()) << "the UPDATE is relayed to the callee";
	EXPECT_EQ(relayed.find("Authorization:"), std::string::npos) << relayed;
}

TEST(InviteAdmission, ARegisterWhoseDigestUriIsNotItsRequestUriIsRefused)
{
	// #549's uri binding covers REGISTER too (admitSecure is shared).
	Harness h;
	SecretGuard guard{"500"};
	ASSERT_TRUE(SipSecretStore::setSecret("500", "s3cret"));
	h.handler.setRegistrarMode(RequestsHandler::RegistrarMode::Secure);
	h.handler.handle(makeRegister("500", "192.168.7.50"));
	const std::string challenge = firstSentContaining(h.sent, "SIP/2.0 401 Unauthorized");
	ASSERT_FALSE(challenge.empty());
	const std::string nonce = paramOf(challenge, "nonce");
	const std::string resp = SipDigest::computeResponse(
		SipDigest::computeHa1("500", SipSecretStore::kRealm, "s3cret"),
		"REGISTER", "sip:elsewhere", nonce, "00000001", "0a4f113b", "auth");

	auto reg = makeRegister("500", "192.168.7.50");
	reg->addHeader("Authorization", "Digest username=\"500\", realm=\"pocketdial\", nonce=\"" + nonce +
		"\", uri=\"sip:elsewhere\", response=\"" + resp +
		"\", algorithm=MD5, qop=auth, nc=00000001, cnonce=\"0a4f113b\"");
	h.sent.clear();
	h.handler.handle(reg);
	EXPECT_TRUE(anySentContains(h.sent, "SIP/2.0 403 Credentials Not For This Request"));
}

TEST(InviteAdmission, ALearnModeForkDropsUnsolicitedCredentials)
{
	// An unsecured Learned caller is never challenged, but a phone may still
	// send credentials unasked; CallForker::buildInviteFork strips them.
	Harness h;
	h.handler.setRegistrarMode(RequestsHandler::RegistrarMode::Learn);
	h.handler.handle(makeInvite("learn560", 1, kPcmuOffer,
		"Authorization: Digest username=\"500\", realm=\"pocketdial\", nonce=\"n\", uri=\"sip:600@server\", response=\"0\"\r\n"));
	const std::string fork = firstSentContaining(h.sent, "INVITE sip:600@");
	ASSERT_FALSE(fork.empty());
	EXPECT_EQ(fork.find("Authorization:"), std::string::npos) << fork;
}

TEST(InviteAdmission, TheBroadcastAckForkCarriesNoCredential)
{
	// #560: onAck's 999 branch clones the caller's ACK for the answering phone
	// (ackFork). A preemptive credential on that ACK must not ride along.
	Harness h;
	const std::string callId = "bc560";
	const std::string body =
		"v=0\r\no=- 0 0 IN IP4 192.168.7.50\r\ns=-\r\nc=IN IP4 192.168.7.50\r\nt=0 0\r\n" +
		std::string(kPcmuOffer) + "a=sendrecv\r\n";
	h.handler.handle(RequestsHandler::getMessageFromPool(
		"INVITE sip:999@server SIP/2.0\r\n"
		"Via: SIP/2.0/UDP 192.168.7.50:5060;branch=z9hG4bKbc560\r\n"
		"From: <sip:500@server>;tag=fbc560\r\n"
		"To: <sip:999@server>\r\n"
		"Call-ID: " + callId + "\r\n"
		"CSeq: 1 INVITE\r\n"
		"Max-Forwards: 70\r\n"
		"Contact: <sip:500@192.168.7.50:5060>\r\n"
		"Content-Type: application/sdp\r\n"
		"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body,
		addrFor("192.168.7.50")));
	const std::string fork = firstSentContaining(h.sent, "INVITE sip:600@");
	ASSERT_FALSE(fork.empty()) << "999 forks to the other registered phone";

	// 600 answers the fork.
	auto viaOf = [](const std::string& raw) {
		const size_t a = raw.find("Via:");
		return raw.substr(a, raw.find("\r\n", a) - a);
	};
	auto fromOf = [](const std::string& raw) {
		const size_t a = raw.find("From:");
		return raw.substr(a, raw.find("\r\n", a) - a);
	};
	const std::string answer = "v=0\r\no=- 0 0 IN IP4 192.168.7.60\r\ns=-\r\nc=IN IP4 192.168.7.60\r\nt=0 0\r\n" +
		std::string(kPcmuOffer) + "a=sendrecv\r\n";
	h.handler.handle(RequestsHandler::getMessageFromPool(
		"SIP/2.0 200 OK\r\n" + viaOf(fork) + "\r\n" + fromOf(fork) + "\r\n"
		"To: <sip:600@server>;tag=ans560\r\n"
		"Call-ID: " + callId + "\r\n"
		"CSeq: 1 INVITE\r\n"
		"Contact: <sip:600@192.168.7.60:5060>\r\n"
		"Content-Type: application/sdp\r\n"
		"Content-Length: " + std::to_string(answer.size()) + "\r\n\r\n" + answer,
		addrFor("192.168.7.60")));

	// The caller ACKs the 200, carrying a (preemptive) credential.
	h.sent.clear();
	h.handler.handle(RequestsHandler::getMessageFromPool(
		"ACK sip:999@server SIP/2.0\r\n"
		"Via: SIP/2.0/UDP 192.168.7.50:5060;branch=z9hG4bKbc560a\r\n"
		"From: <sip:500@server>;tag=fbc560\r\n"
		"To: <sip:999@server>;tag=ans560\r\n"
		"Call-ID: " + callId + "\r\n"
		"CSeq: 1 ACK\r\n"
		"Authorization: Digest username=\"500\", realm=\"pocketdial\", nonce=\"n560\", "
		"uri=\"sip:999@server\", response=\"00000000000000000000000000000000\"\r\n" +
		kProxyAuth +
		"Content-Length: 0\r\n\r\n",
		addrFor("192.168.7.50")));

	const std::string relayed = lastSentTo600Starting(h.sent, "ACK ");
	ASSERT_FALSE(relayed.empty()) << "the 999 ACK is forked to the answering phone";
	EXPECT_EQ(relayed.find("Authorization:"), std::string::npos) << relayed;
}

namespace
{
	// #560: a 999 all-page call from 500 whose fork to 600 is pending, then
	// optionally answered by 600. Returns the fork 600 received.
	std::string startBroadcast(Harness& h, const std::string& callId, bool answer)
	{
		const std::string body =
			"v=0\r\no=- 0 0 IN IP4 192.168.7.50\r\ns=-\r\nc=IN IP4 192.168.7.50\r\nt=0 0\r\n" +
			std::string(kPcmuOffer) + "a=sendrecv\r\n";
		h.handler.handle(RequestsHandler::getMessageFromPool(
			"INVITE sip:999@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP 192.168.7.50:5060;branch=z9hG4bK" + callId + "\r\n"
			"From: <sip:500@server>;tag=f" + callId + "\r\n"
			"To: <sip:999@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Max-Forwards: 70\r\n"
			"Contact: <sip:500@192.168.7.50:5060>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body,
			addrFor("192.168.7.50")));
		const std::string fork = firstSentContaining(h.sent, "INVITE sip:600@");
		if (fork.empty() || !answer) return fork;
		auto lineOf = [&fork](const char* name) {
			const size_t a = fork.find(name);
			return fork.substr(a, fork.find("\r\n", a) - a);
		};
		const std::string sdp = "v=0\r\no=- 0 0 IN IP4 192.168.7.60\r\ns=-\r\nc=IN IP4 192.168.7.60\r\nt=0 0\r\n" +
			std::string(kPcmuOffer) + "a=sendrecv\r\n";
		h.handler.handle(RequestsHandler::getMessageFromPool(
			"SIP/2.0 200 OK\r\n" + lineOf("Via:") + "\r\n" + lineOf("From:") + "\r\n"
			"To: <sip:600@server>;tag=ans" + callId + "\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Contact: <sip:600@192.168.7.60:5060>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(sdp.size()) + "\r\n\r\n" + sdp,
			addrFor("192.168.7.60")));
		return fork;
	}

	const std::string kCallerCredential =
		"Authorization: Digest username=\"500\", realm=\"pocketdial\", nonce=\"n560\", "
		"uri=\"sip:999@server\", response=\"00000000000000000000000000000000\"\r\n";
}

TEST(InviteAdmission, TheBroadcastCancelForkCarriesNoCredential)
{
	// #560: onCancel's 999 branch clones the caller's CANCEL once per ringing
	// target. A credential on that CANCEL must not ride along to them.
	Harness h;
	ASSERT_FALSE(startBroadcast(h, "cx560", /*answer=*/false).empty())
		<< "999 forks to the other registered phone";

	h.sent.clear();
	h.handler.handle(RequestsHandler::getMessageFromPool(
		"CANCEL sip:999@server SIP/2.0\r\n"
		"Via: SIP/2.0/UDP 192.168.7.50:5060;branch=z9hG4bKcx560\r\n"
		"From: <sip:500@server>;tag=fcx560\r\n"
		"To: <sip:999@server>\r\n"
		"Call-ID: cx560\r\n"
		"CSeq: 1 CANCEL\r\n" + kCallerCredential + kProxyAuth +
		"Content-Length: 0\r\n\r\n",
		addrFor("192.168.7.50")));

	const std::string relayed = lastSentTo600Starting(h.sent, "CANCEL ");
	ASSERT_FALSE(relayed.empty()) << "the CANCEL is forked to the ringing phone";
	EXPECT_EQ(relayed.find("Authorization:"), std::string::npos) << relayed;
}

TEST(InviteAdmission, TheBroadcastByeForkCarriesNoCredential)
{
	// #560: onBye's 999 branch clones the caller's BYE for the answering phone
	// (byeFork). A credential on that BYE must not ride along.
	Harness h;
	ASSERT_FALSE(startBroadcast(h, "by560", /*answer=*/true).empty());

	h.sent.clear();
	h.handler.handle(RequestsHandler::getMessageFromPool(
		"BYE sip:999@server SIP/2.0\r\n"
		"Via: SIP/2.0/UDP 192.168.7.50:5060;branch=z9hG4bKby560b\r\n"
		"From: <sip:500@server>;tag=fby560\r\n"
		"To: <sip:999@server>;tag=ansby560\r\n"
		"Call-ID: by560\r\n"
		"CSeq: 2 BYE\r\n" + kCallerCredential + kProxyAuth +
		"Content-Length: 0\r\n\r\n",
		addrFor("192.168.7.50")));

	const std::string relayed = lastSentTo600Starting(h.sent, "BYE ");
	ASSERT_FALSE(relayed.empty()) << "the 999 BYE is forked to the answering phone";
	EXPECT_EQ(relayed.find("Authorization:"), std::string::npos) << relayed;
}
