// RegisterIdentityGuard_test.cpp — Issue #163: REGISTER admits reserved,
// emergency, and PSTN-shaped identities with no check beyond isValidAor()'s
// charset filter.
//
// The pure logic behind the guard (pbx::isReservedExtension() /
// pbx::looksLikePstnAor() / pbx::isReservedOrPstnAor(), all in PbxConfig.hpp)
// is unit-tested in Pbx_test.cpp, which deliberately stays free of
// RequestsHandler. What is under test HERE is the wire-level behaviour the
// issue actually cares about: driving a real RequestsHandler through
// handle(), in every registrar mode, and asserting on the bytes it sends —
// in the style of ServiceExtensions_test.cpp (Issue #202), which this guard
// sits directly beside in onRegister().
//
// Scope note on the issue's second named call site (the device-registry
// "rename" path, findProvisioningInfo()'s d.extension recheck): it cannot be
// exercised end to end from a host test. findProvisioningInfo() only ever
// sees a device that Learn-mode admission adopted, and that adoption path is
// gated on ArpLookup::pdLookupMac() resolving a source IP to a MAC —
// unconditionally std::nullopt on host builds (see ArpLookup.cpp's host
// stub), with no seam to inject a fake resolution anywhere in the codebase.
// That makes admitLearn()'s "known MAC" branch — and everything downstream
// of it, including findProvisioningInfo() ever seeing a non-empty registry —
// dead code in every host test that exists today, not something this change
// made newly untestable. The onRegister() guard below is what actually gates
// this in practice (it runs before admitLearn() is ever reached), and its
// logic is the same pbx::isReservedOrPstnAor() already covered in
// Pbx_test.cpp.

#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <vector>

#include "RequestsHandler.hpp"
#include "SipDigest.hpp"
#include "SipSecretStore.hpp"

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

namespace
{
	sockaddr_in ridAddr(const std::string& ip)
	{
		sockaddr_in s{};
		s.sin_family = AF_INET;
		s.sin_addr.s_addr = inet_addr(ip.c_str());
		s.sin_port = htons(5060);
		return s;
	}

	// callId must be unique per REGISTER within a test (it seeds Via branch,
	// From-tag and Call-ID alike, same as ServiceExtensions_test.cpp's helper).
	std::shared_ptr<SipMessage> ridRegister(const std::string& ext, const std::string& srcIp,
	                                        const std::string& callId)
	{
		std::string raw =
			"REGISTER sip:server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + srcIp + ":5060;branch=z9hG4bKr" + callId + "\r\n"
			"From: <sip:" + ext + "@server>;tag=rt" + callId + "\r\n"
			"To: <sip:" + ext + "@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 REGISTER\r\n"
			"Contact: <sip:" + ext + "@" + srcIp + ":5060>;expires=3600\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, ridAddr(srcIp));
	}

	std::shared_ptr<SipMessage> ridRegisterWithAuth(const std::string& ext, const std::string& srcIp,
	                                                const std::string& callId, int cseq,
	                                                const std::string& authHeader)
	{
		std::string raw =
			"REGISTER sip:server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + srcIp + ":5060;branch=z9hG4bKr" + callId + std::to_string(cseq) + "\r\n"
			"From: <sip:" + ext + "@server>;tag=rt" + callId + "\r\n"
			"To: <sip:" + ext + "@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: " + std::to_string(cseq) + " REGISTER\r\n"
			"Contact: <sip:" + ext + "@" + srcIp + ":5060>;expires=3600\r\n" +
			authHeader +
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, ridAddr(srcIp));
	}

	struct RidWire
	{
		std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>> sent;

		void clear() { sent.clear(); }

		std::vector<std::string> raws() const
		{
			std::vector<std::string> out;
			out.reserve(sent.size());
			for (const auto& entry : sent)
			{
				out.push_back(entry.second ? entry.second->toString() : std::string{});
			}
			return out;
		}

		bool sawContaining(const std::string& needle) const
		{
			for (const auto& raw : raws())
			{
				if (raw.find(needle) != std::string::npos) return true;
			}
			return false;
		}

		std::string firstContaining(const std::string& needle) const
		{
			for (const auto& raw : raws())
			{
				if (raw.find(needle) != std::string::npos) return raw;
			}
			return {};
		}
	};

	std::string paramOf(const std::string& raw, const std::string& key)
	{
		size_t p = raw.find(key + "=\"");
		if (p == std::string::npos) return {};
		p += key.size() + 2;
		size_t e = raw.find('"', p);
		return raw.substr(p, e - p);
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// 1. Every reserved/emergency literal is refused, in every registrar mode
// ═══════════════════════════════════════════════════════════════════════════

TEST(RegisterIdentityGuard, ReservedAndEmergencyExtensionsRefusedInOpenMode)
{
	RidWire wire;
	RequestsHandler handler("192.168.50.1", 5060,
		[&wire](const sockaddr_in& a, std::shared_ptr<SipMessage> m) {
			wire.sent.emplace_back(a, std::move(m));
		});

	int i = 0;
	for (const char* ext : {"777", "999", "888", "555", "440", "911", "933"})
	{
		wire.clear();
		handler.handle(ridRegister(ext, "192.168.50.10", "open-" + std::to_string(++i)));
		EXPECT_TRUE(wire.sawContaining("SIP/2.0 403 Reserved or PSTN-shaped extension"))
			<< "ext " << ext << " must be refused, even in Open mode";
		EXPECT_FALSE(wire.sawContaining("SIP/2.0 200 OK")) << "ext " << ext;
	}
}

TEST(RegisterIdentityGuard, ReservedAndEmergencyExtensionsRefusedInLearnMode)
{
	RidWire wire;
	RequestsHandler handler("192.168.50.2", 5060,
		[&wire](const sockaddr_in& a, std::shared_ptr<SipMessage> m) {
			wire.sent.emplace_back(a, std::move(m));
		});
	handler.setRegistrarMode(RequestsHandler::RegistrarMode::Learn);

	int i = 0;
	for (const char* ext : {"777", "999", "888", "555", "440", "911", "933"})
	{
		wire.clear();
		handler.handle(ridRegister(ext, "192.168.50.11", "learn-" + std::to_string(++i)));
		EXPECT_TRUE(wire.sawContaining("SIP/2.0 403 Reserved or PSTN-shaped extension"))
			<< "ext " << ext << " must be refused in Learn mode -- squatting is exactly "
			   "what TOFU adoption must not permit";
		EXPECT_FALSE(wire.sawContaining("SIP/2.0 200 OK")) << "ext " << ext;
	}

	handler.setRegistrarMode(RequestsHandler::RegistrarMode::Open);
}

TEST(RegisterIdentityGuard, ReservedAndEmergencyExtensionsRefusedInSecureModeBeforeAnyChallenge)
{
	// The point of this test: the guard must fire BEFORE admitSecure() gets a
	// chance to answer "Extension Not Provisioned" (403) or challenge (401) for
	// these names. Asserting the FULL status line (not a bare "403") is what
	// proves it was THIS guard and not Secure mode's own unprovisioned-extension
	// rejection, which is also a 403 with a different reason phrase.
	RidWire wire;
	RequestsHandler handler("192.168.50.3", 5060,
		[&wire](const sockaddr_in& a, std::shared_ptr<SipMessage> m) {
			wire.sent.emplace_back(a, std::move(m));
		});
	handler.setRegistrarMode(RequestsHandler::RegistrarMode::Secure);

	int i = 0;
	for (const char* ext : {"777", "999", "888", "555", "440", "911", "933"})
	{
		wire.clear();
		handler.handle(ridRegister(ext, "192.168.50.12", "secure-" + std::to_string(++i)));
		EXPECT_TRUE(wire.sawContaining("SIP/2.0 403 Reserved or PSTN-shaped extension"))
			<< "ext " << ext;
		EXPECT_FALSE(wire.sawContaining("401 Unauthorized"))
			<< "ext " << ext << " must never even be challenged";
		EXPECT_FALSE(wire.sawContaining("Extension Not Provisioned"))
			<< "ext " << ext << " must be refused by the identity guard, not Secure "
			   "mode's separate unprovisioned-extension rejection";
	}

	handler.setRegistrarMode(RequestsHandler::RegistrarMode::Open);
}

// ═══════════════════════════════════════════════════════════════════════════
// 2. A normal extension is unaffected, in every registrar mode
// ═══════════════════════════════════════════════════════════════════════════

TEST(RegisterIdentityGuard, OrdinaryExtensionStillRegistersInOpenMode)
{
	RidWire wire;
	RequestsHandler handler("192.168.50.4", 5060,
		[&wire](const sockaddr_in& a, std::shared_ptr<SipMessage> m) {
			wire.sent.emplace_back(a, std::move(m));
		});

	handler.handle(ridRegister("101", "192.168.50.13", "open-ok"));
	EXPECT_TRUE(wire.sawContaining("SIP/2.0 200 OK"));
	EXPECT_FALSE(wire.sawContaining("SIP/2.0 403"));
}

TEST(RegisterIdentityGuard, OrdinaryExtensionStillRegistersInLearnMode)
{
	// Host build: ArpLookup::pdLookupMac() is a permanent miss, so Learn mode
	// takes its documented "ARP miss, deferring MAC-lock" branch and accepts --
	// this is the cheap, deterministic half of Learn-mode admission to assert on
	// from a host test (see the file header for why the MAC-lock branch is not).
	RidWire wire;
	RequestsHandler handler("192.168.50.5", 5060,
		[&wire](const sockaddr_in& a, std::shared_ptr<SipMessage> m) {
			wire.sent.emplace_back(a, std::move(m));
		});
	handler.setRegistrarMode(RequestsHandler::RegistrarMode::Learn);

	handler.handle(ridRegister("102", "192.168.50.14", "learn-ok"));
	EXPECT_TRUE(wire.sawContaining("SIP/2.0 200 OK"));
	EXPECT_FALSE(wire.sawContaining("SIP/2.0 403"));

	handler.setRegistrarMode(RequestsHandler::RegistrarMode::Open);
}

TEST(RegisterIdentityGuard, OrdinaryExtensionStillChallengedThenAdmittedInSecureMode)
{
	// Proves the guard does not over-match: a provisioned, ordinary extension
	// must reach Secure mode's OWN admission (401 challenge, then 200 on valid
	// credentials) rather than being swept up by the identity guard.
	RidWire wire;
	RequestsHandler handler("192.168.50.6", 5060,
		[&wire](const sockaddr_in& a, std::shared_ptr<SipMessage> m) {
			wire.sent.emplace_back(a, std::move(m));
		});
	ASSERT_TRUE(SipSecretStore::setSecret("103", "s3cret"));
	handler.setRegistrarMode(RequestsHandler::RegistrarMode::Secure);

	handler.handle(ridRegister("103", "192.168.50.15", "sec-ok"));
	const std::string challenge = wire.firstContaining("SIP/2.0 401 Unauthorized");
	ASSERT_FALSE(challenge.empty()) << "an ordinary provisioned extension must still "
		"be challenged, not refused by the identity guard";
	EXPECT_FALSE(wire.sawContaining("SIP/2.0 403"));

	const std::string nonce = paramOf(challenge, "nonce");
	ASSERT_FALSE(nonce.empty());
	const std::string ha1 = SipDigest::computeHa1("103", SipSecretStore::kRealm, "s3cret");
	const std::string response = SipDigest::computeResponse(
		ha1, "REGISTER", "sip:server", nonce, "00000001", "0a4f113b", "auth");
	const std::string authz =
		"Authorization: Digest username=\"103\", realm=\"pocketdial\", nonce=\"" + nonce +
		"\", uri=\"sip:server\", response=\"" + response +
		"\", algorithm=MD5, qop=auth, nc=00000001, cnonce=\"0a4f113b\"\r\n";

	wire.clear();
	handler.handle(ridRegisterWithAuth("103", "192.168.50.15", "sec-ok", 2, authz));
	EXPECT_TRUE(wire.sawContaining("SIP/2.0 200 OK"));
	EXPECT_FALSE(wire.sawContaining("SIP/2.0 403"));

	SipSecretStore::clearSecret("103");
	handler.setRegistrarMode(RequestsHandler::RegistrarMode::Open);
}

// ═══════════════════════════════════════════════════════════════════════════
// 3. E.164 ('+'-prefixed) and PSTN-shaped AORs are refused
// ═══════════════════════════════════════════════════════════════════════════

TEST(RegisterIdentityGuard, PlusPrefixedAorRefusedRegardlessOfMode)
{
	RidWire wire;
	RequestsHandler handler("192.168.50.7", 5060,
		[&wire](const sockaddr_in& a, std::shared_ptr<SipMessage> m) {
			wire.sent.emplace_back(a, std::move(m));
		});

	handler.handle(ridRegister("+15551234567", "192.168.50.16", "plus-open"));
	EXPECT_TRUE(wire.sawContaining("SIP/2.0 403 Reserved or PSTN-shaped extension"));
	EXPECT_FALSE(wire.sawContaining("SIP/2.0 200 OK"));

	handler.setRegistrarMode(RequestsHandler::RegistrarMode::Learn);
	wire.clear();
	handler.handle(ridRegister("+15551234567", "192.168.50.17", "plus-learn"));
	EXPECT_TRUE(wire.sawContaining("SIP/2.0 403 Reserved or PSTN-shaped extension"));

	handler.setRegistrarMode(RequestsHandler::RegistrarMode::Open);
}

TEST(RegisterIdentityGuard, LongAllDigitPstnShapedAorRefused)
{
	RidWire wire;
	RequestsHandler handler("192.168.50.8", 5060,
		[&wire](const sockaddr_in& a, std::shared_ptr<SipMessage> m) {
			wire.sent.emplace_back(a, std::move(m));
		});

	// 10 digits, no '+' -- unambiguously PSTN-shaped by the configured default
	// threshold (POCKETDIAL_MIN_PSTN_AOR_DIGITS = 7).
	handler.handle(ridRegister("5551234567", "192.168.50.18", "pstn-shaped"));
	EXPECT_TRUE(wire.sawContaining("SIP/2.0 403 Reserved or PSTN-shaped extension"));
	EXPECT_FALSE(wire.sawContaining("SIP/2.0 200 OK"));
}

// ═══════════════════════════════════════════════════════════════════════════
// 4. A refused REGISTER leaves no binding: the security property, observed
// ═══════════════════════════════════════════════════════════════════════════

TEST(RegisterIdentityGuard, RefusedRegistrationAs911BindsNothingSoDialing911StillMisses)
{
	// The exact scenario the issue is about: before this guard, a squatter
	// REGISTERing as "911" would have received every call dialed to it. Prove
	// the refusal is not merely cosmetic (a 403 on the wire) by dialing "911"
	// from a real registered client afterwards and requiring the SAME 404 an
	// unclaimed number gets -- not a call forwarded to the squatter's address.
	RidWire wire;
	RequestsHandler handler("192.168.50.9", 5060,
		[&wire](const sockaddr_in& a, std::shared_ptr<SipMessage> m) {
			wire.sent.emplace_back(a, std::move(m));
		});

	handler.handle(ridRegister("911", "192.168.50.66", "squat-911"));
	wire.clear();

	handler.handle(ridRegister("101", "192.168.50.19", "reg-101"));
	wire.clear();

	std::string body =
		"v=0\r\n"
		"o=- 0 0 IN IP4 192.168.50.19\r\n"
		"s=-\r\n"
		"c=IN IP4 192.168.50.19\r\n"
		"t=0 0\r\n"
		"m=audio 10000 RTP/AVP 0 101\r\n"
		"a=rtpmap:0 PCMU/8000\r\n"
		"a=rtpmap:101 telephone-event/8000\r\n"
		"a=sendrecv\r\n";
	std::string raw =
		"INVITE sip:911@server SIP/2.0\r\n"
		"Via: SIP/2.0/UDP 192.168.50.19:5060;branch=z9hG4bKidial911\r\n"
		"From: <sip:101@server>;tag=ftdial911\r\n"
		"To: <sip:911@server>\r\n"
		"Call-ID: call-dial-911\r\n"
		"CSeq: 1 INVITE\r\n"
		"Max-Forwards: 70\r\n"
		"Contact: <sip:101@192.168.50.19:5060>\r\n"
		"Content-Type: application/sdp\r\n"
		"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
	handler.handle(RequestsHandler::getMessageFromPool(raw, ridAddr("192.168.50.19")));

	EXPECT_FALSE(wire.sawContaining("INVITE sip:911@192.168.50.66"))
		<< "the refused REGISTER must not have bound 911 to the squatter's address";
	EXPECT_TRUE(wire.sawContaining("SIP/2.0 404 Not Found"))
		<< "911 must miss exactly like any other unclaimed number today "
		   "(this codebase has no emergency-routing rule yet -- that is the "
		   "companion issue's scope, not #163's)";
}
