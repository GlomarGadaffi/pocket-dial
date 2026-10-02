// Issue #826: SIP Plug-and-Play discovery.
//
// PnpProfile parses the ua-profile SUBSCRIBE a factory-fresh phone multicasts
// to 224.0.1.75:5060 and writes the 200 OK and the NOTIFY that hands it a
// config URL. PnpResponder decides who gets answered. Both are pure, so every
// rule is tested here without a socket. Also: the snom renderer and its
// /config/snom<mac>.xml route shape, and that the per-datagram path allocates
// nothing.

#include <gtest/gtest.h>

#include <array>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <string>
#include <string_view>

#include "HttpServer.hpp"
#include "PnpProfile.hpp"
#include "PnpResponder.hpp"
#include "ProvisioningConfig.hpp"
#include "support/AllocCounter.hpp"

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

namespace
{
	// SYNTHETIC: written from the PnP spec's message shape with this bench's
	// snom370 identity, so the edge-case tests below can patch it. The real
	// wire capture is kSnomCaptured, right after it.
	const std::string kSnomSubscribe =
		"SUBSCRIBE sip:MAC%3a0004132E08B4@224.0.1.75 SIP/2.0\r\n"
		"Via: SIP/2.0/UDP 192.168.12.155:5060;branch=z9hG4bK-snom-1;rport\r\n"
		"From: <sip:MAC%3a0004132E08B4@224.0.1.75>;tag=abc123\r\n"
		"To: <sip:MAC%3a0004132E08B4@224.0.1.75>\r\n"
		"Call-ID: 3c26700857f2-pnp@192.168.12.155\r\n"
		"CSeq: 1 SUBSCRIBE\r\n"
		"Max-Forwards: 70\r\n"
		"Event: ua-profile;profile-type=\"device\";vendor=\"snom\";model=\"snom370\";version=\"8.7.5.48\"\r\n"
		"Expires: 0\r\n"
		"Accept: application/url\r\n"
		"Contact: <sip:192.168.12.155:5060>\r\n"
		"Content-Length: 0\r\n"
		"\r\n";

	// CAPTURED: the snom370 (8.7.5.48) on the bench, its own SIP trace,
	// "Sent to udp:224.0.1.75:5060 at Oct 2 01:15:53.729 (442 bytes)". Note
	// what the synthetic one got wrong: source port 1053 (not 5060), a Via
	// with rport and NO branch, and a Request-URI host of "lan".
	const std::string kSnomCaptured =
		"SUBSCRIBE sip:MAC%3a0004132E08B4@lan SIP/2.0\r\n"
		"Via: SIP/2.0/UDP 192.168.12.155:1053;rport\r\n"
		"From: <sip:MAC%3a0004132E08B4@lan>;tag=668717252\r\n"
		"To: <sip:MAC%3a0004132E08B4@lan>\r\n"
		"Call-ID: 949137397@192.168.12.155\r\n"
		"CSeq: 1 SUBSCRIBE\r\n"
		"Event: ua-profile;profile-type=\"device\";vendor=\"snom\";model=\"snom370\";version=\"8.7.5.48\"\r\n"
		"Expires: 0\r\n"
		"Accept: application/url\r\n"
		"Contact: <sip:192.168.12.155:1053>\r\n"
		"User-Agent: snom370/8.7.5.48\r\n"
		"Content-Length: 0\r\n"
		"\r\n";

	std::string replace(std::string s, const std::string& from, const std::string& to)
	{
		const size_t at = s.find(from);
		if (at != std::string::npos) s.replace(at, from.size(), to);
		return s;
	}

	sockaddr_in addr(const char* ip, uint16_t port = 5060)
	{
		sockaddr_in a{};
		a.sin_family = AF_INET;
		inet_pton(AF_INET, ip, &a.sin_addr);
		a.sin_port = htons(port);
		return a;
	}

	uint32_t ipOf(const char* ip)
	{
		in_addr a{};
		inet_pton(AF_INET, ip, &a);
		return a.s_addr;
	}

	std::string str(const std::array<char, pnp::kFieldCap>& a) { return std::string(a.data()); }
	std::string str(const std::array<char, pnp::kMacCap>& a) { return std::string(a.data()); }

	// A responder on 192.168.12.195/24, port 5060, in `mode`.
	struct Bench
	{
		PnpResponder r;
		explicit Bench(PnpResponder::Mode mode)
		{
			r.setNetwork(ipOf("192.168.12.195"), ipOf("255.255.255.0"), 5060);
			r.setMode(mode);
		}
		PnpResponder::Reply feed(const std::string& raw, const char* from, uint32_t now, bool serve = true)
		{
			auto canServe = [serve](std::string_view) { return serve; };
			return r.onDatagram(raw, addr(from), now, canServe);
		}
		size_t count()
		{
			return r.forEachDevice([](const PnpResponder::Device&) {});
		}
	};
}

// ── PnpProfile::parseSubscribe ───────────────────────────────────────────────

TEST(PnpProfile, ParsesSnomSubscribe)
{
	pnp::Subscribe s;
	ASSERT_TRUE(pnp::parseSubscribe(kSnomSubscribe, s));
	EXPECT_EQ(str(s.id.mac), "0004132e08b4");
	EXPECT_EQ(str(s.id.vendor), "snom");
	EXPECT_EQ(str(s.id.model), "snom370");
	EXPECT_EQ(str(s.id.version), "8.7.5.48");
	EXPECT_EQ(s.viaCount, 1u);
	EXPECT_EQ(s.callId, "3c26700857f2-pnp@192.168.12.155");
	EXPECT_EQ(s.cseq, "1 SUBSCRIBE");
	EXPECT_EQ(pnp::vendorOf(s.id), pnp::Vendor::Snom);
}

TEST(PnpProfile, ParsesARealSnom370CaptureAndAnswersItsSourcePort)
{
	pnp::Subscribe s;
	ASSERT_TRUE(pnp::parseSubscribe(kSnomCaptured, s));
	EXPECT_EQ(str(s.id.mac), "0004132e08b4");
	EXPECT_EQ(str(s.id.model), "snom370");
	EXPECT_EQ(s.vias[0], "SIP/2.0/UDP 192.168.12.155:1053;rport");
	EXPECT_EQ(s.expires, 0u);

	Bench b(PnpResponder::Mode::Provision);
	auto yes = [](std::string_view) { return true; };
	const auto r = b.r.onDatagram(kSnomCaptured, addr("192.168.12.155", 1053), 100, yes);
	ASSERT_FALSE(r.notify.empty());
	EXPECT_EQ(std::string(r.notify).rfind("NOTIFY sip:192.168.12.155:1053 SIP/2.0\r\n", 0), 0u);
	EXPECT_NE(std::string(r.ok).find("Expires: 0\r\n"), std::string::npos);
}

TEST(PnpProfile, AcceptsCompactHeadersAndMacColonForm)
{
	const std::string raw =
		"SUBSCRIBE sip:MAC:0015654093A7@224.0.1.75 SIP/2.0\n"
		"v: SIP/2.0/UDP 192.168.12.204:5060;branch=z9hG4bK1\n"
		"v: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK2\n"
		"f: <sip:MAC:0015654093A7@224.0.1.75>;tag=1\n"
		"t: <sip:MAC:0015654093A7@224.0.1.75>\n"
		"i: yl-1\n"
		"CSeq: 7 SUBSCRIBE\n"
		"o: UA-Profile ; profile-type=device ; vendor=\"Yealink\" ; model=\"SIP-T32G\" ; version=\"32.70.0.228\"\n"
		"\n";
	pnp::Subscribe s;
	ASSERT_TRUE(pnp::parseSubscribe(raw, s));
	EXPECT_EQ(str(s.id.mac), "0015654093a7");
	EXPECT_EQ(str(s.id.model), "SIP-T32G");
	EXPECT_EQ(s.viaCount, 2u);
	EXPECT_EQ(pnp::vendorOf(s.id), pnp::Vendor::Yealink);
}

TEST(PnpProfile, TakesMacFromToWhenFromHasNone)
{
	const std::string raw = replace(kSnomSubscribe,
		"From: <sip:MAC%3a0004132E08B4@224.0.1.75>;tag=abc123", "From: <sip:anonymous@224.0.1.75>;tag=abc123");
	pnp::Subscribe s;
	ASSERT_TRUE(pnp::parseSubscribe(raw, s));
	EXPECT_EQ(str(s.id.mac), "0004132e08b4");
}

TEST(PnpProfile, RejectsWhatIsNotADiscoveryRequest)
{
	pnp::Subscribe s;
	EXPECT_FALSE(pnp::parseSubscribe(replace(kSnomSubscribe, "SUBSCRIBE sip:", "OPTIONS sip:"), s));
	EXPECT_FALSE(pnp::parseSubscribe(replace(kSnomSubscribe, "ua-profile;", "dialog;"), s));
	EXPECT_FALSE(pnp::parseSubscribe(replace(kSnomSubscribe, "profile-type=\"device\"", "profile-type=\"user\""), s));
	EXPECT_FALSE(pnp::parseSubscribe(replace(kSnomSubscribe, "Call-ID: 3c26700857f2-pnp@192.168.12.155\r\n", ""), s));
	EXPECT_FALSE(pnp::parseSubscribe(replace(kSnomSubscribe, "Via: SIP/2.0/UDP 192.168.12.155:5060;branch=z9hG4bK-snom-1;rport\r\n", ""), s));
	// In-dialog (To already tagged): not discovery.
	EXPECT_FALSE(pnp::parseSubscribe(replace(kSnomSubscribe, "To: <sip:MAC%3a0004132E08B4@224.0.1.75>",
		"To: <sip:MAC%3a0004132E08B4@224.0.1.75>;tag=xyz"), s));
	// No MAC anywhere, a short MAC, a non-hex MAC.
	std::string noMac = replace(kSnomSubscribe, "From: <sip:MAC%3a0004132E08B4@", "From: <sip:phone@");
	noMac = replace(noMac, "To: <sip:MAC%3a0004132E08B4@", "To: <sip:phone@");
	EXPECT_FALSE(pnp::parseSubscribe(noMac, s));
	std::string shortMac = replace(kSnomSubscribe, "From: <sip:MAC%3a0004132E08B4@", "From: <sip:MAC%3a0004132E08B@");
	shortMac = replace(shortMac, "To: <sip:MAC%3a0004132E08B4@", "To: <sip:MAC%3a0004132E08B@");
	EXPECT_FALSE(pnp::parseSubscribe(shortMac, s));
	std::string badHex = replace(kSnomSubscribe, "From: <sip:MAC%3a0004132E08B4@", "From: <sip:MAC%3a0004132E08BZ@");
	badHex = replace(badHex, "To: <sip:MAC%3a0004132E08B4@", "To: <sip:MAC%3a0004132E08BZ@");
	EXPECT_FALSE(pnp::parseSubscribe(badHex, s));
	EXPECT_FALSE(pnp::parseSubscribe("", s));
}

TEST(PnpProfile, RefusesADatagramCutBeforeItsHeadersEnd)
{
	pnp::Subscribe s;
	const std::string cut = kSnomSubscribe.substr(0, kSnomSubscribe.find("Accept:"));
	EXPECT_FALSE(pnp::parseSubscribe(cut, s));
	EXPECT_TRUE(pnp::parseSubscribe(kSnomSubscribe, s));
}

TEST(PnpProfile, OkNeverGrantsLongerThanAsked)
{
	std::array<char, 1400> buf{};
	auto expiresIn = [&buf](const std::string& raw) {
		pnp::Subscribe s;
		if (!pnp::parseSubscribe(raw, s)) return std::string("parse failed");
		const size_t n = pnp::writeOk(s, "t", "192.168.12.195", 5060, buf.data(), buf.size());
		const std::string ok(buf.data(), n);
		const size_t at = ok.find("Expires: ");
		return ok.substr(at + 9, ok.find("\r\n", at) - at - 9);
	};
	EXPECT_EQ(expiresIn(kSnomSubscribe), "0");
	EXPECT_EQ(expiresIn(replace(kSnomSubscribe, "Expires: 0", "Expires: 3600")), "30");
	EXPECT_EQ(expiresIn(replace(kSnomSubscribe, "Expires: 0\r\n", "")), "30");
}

TEST(PnpProfile, SanitizesAndTruncatesWhatThePhoneSaysAboutItself)
{
	const std::string raw = replace(kSnomSubscribe, "model=\"snom370\"",
		"model=\"snom<370>\\\"evil;x\"");
	pnp::Subscribe s;
	ASSERT_TRUE(pnp::parseSubscribe(raw, s));
	for (char c : str(s.id.model)) EXPECT_TRUE(std::isalnum(static_cast<unsigned char>(c)) || std::strchr(".-_+/ ", c));
	const std::string longVendor = replace(kSnomSubscribe, "vendor=\"snom\"",
		"vendor=\"snom" + std::string(100, 'x') + "\"");
	ASSERT_TRUE(pnp::parseSubscribe(longVendor, s));
	EXPECT_EQ(str(s.id.vendor).size(), pnp::kFieldCap - 1);
}

// ── PnpProfile writers ───────────────────────────────────────────────────────

TEST(PnpProfile, UrlIsAFileForSnomAndADirectoryForOthers)
{
	pnp::Subscribe s;
	ASSERT_TRUE(pnp::parseSubscribe(kSnomSubscribe, s));
	std::array<char, 96> buf{};
	size_t n = pnp::writeUrl(s.id, "192.168.12.195", buf.data(), buf.size());
	EXPECT_EQ(std::string(buf.data(), n), "http://192.168.12.195/config/snom0004132e08b4.xml");
	std::strcpy(s.id.vendor.data(), "Yealink");
	n = pnp::writeUrl(s.id, "192.168.12.195", buf.data(), buf.size());
	EXPECT_EQ(std::string(buf.data(), n), "http://192.168.12.195/config/");
	EXPECT_EQ(pnp::writeUrl(s.id, "192.168.12.195", buf.data(), 10), 0u);   // too small: nothing, not a cut URL
}

TEST(PnpProfile, OkEchoesTheTransactionAndTagsTheDialog)
{
	pnp::Subscribe s;
	ASSERT_TRUE(pnp::parseSubscribe(kSnomSubscribe, s));
	std::array<char, 1400> buf{};
	const size_t n = pnp::writeOk(s, "pdTAG", "192.168.12.195", 5060, buf.data(), buf.size());
	ASSERT_GT(n, 0u);
	const std::string ok(buf.data(), n);
	EXPECT_EQ(ok.rfind("SIP/2.0 200 OK\r\n", 0), 0u);
	EXPECT_NE(ok.find("Via: SIP/2.0/UDP 192.168.12.155:5060;branch=z9hG4bK-snom-1;rport\r\n"), std::string::npos);
	EXPECT_NE(ok.find("To: <sip:MAC%3a0004132E08B4@224.0.1.75>;tag=pdTAG\r\n"), std::string::npos);
	EXPECT_NE(ok.find("Call-ID: 3c26700857f2-pnp@192.168.12.155\r\n"), std::string::npos);
	EXPECT_NE(ok.find("CSeq: 1 SUBSCRIBE\r\n"), std::string::npos);
	EXPECT_EQ(ok.substr(ok.size() - 4), "\r\n\r\n");
	EXPECT_EQ(pnp::writeOk(s, "pdTAG", "192.168.12.195", 5060, buf.data(), 64), 0u);
}

TEST(PnpProfile, NotifyCarriesTheUrlToTheSource)
{
	pnp::Subscribe s;
	ASSERT_TRUE(pnp::parseSubscribe(kSnomSubscribe, s));
	const std::string url = "http://192.168.12.195/config/snom0004132e08b4.xml";
	std::array<char, 1400> buf{};
	const size_t n = pnp::writeNotify(s, "pdTAG", "z9hG4bKpnp1", "192.168.12.195", 5060,
		"192.168.12.155", 5060, url, buf.data(), buf.size());
	ASSERT_GT(n, 0u);
	const std::string msg(buf.data(), n);
	EXPECT_EQ(msg.rfind("NOTIFY sip:192.168.12.155:5060 SIP/2.0\r\n", 0), 0u);
	EXPECT_NE(msg.find("From: <sip:MAC%3a0004132E08B4@224.0.1.75>;tag=pdTAG\r\n"), std::string::npos);
	EXPECT_NE(msg.find("To: <sip:MAC%3a0004132E08B4@224.0.1.75>;tag=abc123\r\n"), std::string::npos);
	EXPECT_NE(msg.find("Event: ua-profile;profile-type=\"device\";vendor=\"snom\";model=\"snom370\";version=\"8.7.5.48\"\r\n"),
		std::string::npos);
	EXPECT_NE(msg.find("Content-Type: application/url\r\n"), std::string::npos);
	EXPECT_NE(msg.find("Content-Length: " + std::to_string(url.size()) + "\r\n\r\n"), std::string::npos);
	EXPECT_EQ(msg.substr(msg.size() - url.size()), url);
}

// ── PnpResponder policy ──────────────────────────────────────────────────────

TEST(PnpResponder, OffIgnoresEverything)
{
	Bench b(PnpResponder::Mode::Off);
	const auto r = b.feed(kSnomSubscribe, "192.168.12.155", 100);
	EXPECT_TRUE(r.ok.empty());
	EXPECT_TRUE(r.notify.empty());
	EXPECT_EQ(b.count(), 0u);
}

TEST(PnpResponder, DiscoverRecordsButNeverAnswers)
{
	Bench b(PnpResponder::Mode::Discover);
	const auto r = b.feed(kSnomSubscribe, "192.168.12.155", 100);
	EXPECT_TRUE(r.ok.empty());
	EXPECT_TRUE(r.notify.empty());
	ASSERT_EQ(b.count(), 1u);
	b.r.forEachDevice([](const PnpResponder::Device& d) {
		EXPECT_EQ(std::string(d.id.mac.data()), "0004132e08b4");
		EXPECT_EQ(d.ip, ipOf("192.168.12.155"));
		EXPECT_EQ(d.seen, 1u);
		EXPECT_FALSE(d.notified);
	});
}

TEST(PnpResponder, ProvisionAnswersOnlyPhonesThisBoardCanServe)
{
	Bench b(PnpResponder::Mode::Provision);
	auto r = b.feed(kSnomSubscribe, "192.168.12.155", 100, /*serve=*/false);
	EXPECT_TRUE(r.ok.empty());   // silence: another server may still answer
	EXPECT_TRUE(r.notify.empty());
	EXPECT_EQ(b.count(), 1u);    // but it is still listed

	r = b.feed(kSnomSubscribe, "192.168.12.155", 101, /*serve=*/true);
	ASSERT_FALSE(r.ok.empty());
	ASSERT_FALSE(r.notify.empty());
	EXPECT_NE(std::string(r.notify).find("NOTIFY sip:192.168.12.155:5060 SIP/2.0"), std::string::npos);
	EXPECT_NE(std::string(r.notify).find("http://192.168.12.195/config/snom0004132e08b4.xml"), std::string::npos);
}

TEST(PnpResponder, AVendorWithNoUrlShapeGetsSilence)
{
	// A URL that 404s is worse than no answer: the phone stores it anyway.
	Bench b(PnpResponder::Mode::Provision);
	const auto r = b.feed(replace(kSnomSubscribe, "vendor=\"snom\"", "vendor=\"Acme\""), "192.168.12.155", 100);
	EXPECT_TRUE(r.ok.empty());
	EXPECT_TRUE(r.notify.empty());
	EXPECT_EQ(b.count(), 1u);   // still listed
}

TEST(PnpResponder, IgnoresSourcesOffTheBoardsSubnet)
{
	Bench b(PnpResponder::Mode::Provision);
	const auto r = b.feed(kSnomSubscribe, "10.9.9.9", 100);
	EXPECT_TRUE(r.ok.empty());
	EXPECT_EQ(b.count(), 0u);
}

TEST(PnpResponder, IgnoresEverythingUntilTheNetworkIsKnown)
{
	PnpResponder r;
	r.setMode(PnpResponder::Mode::Provision);
	auto yes = [](std::string_view) { return true; };
	const auto out = r.onDatagram(kSnomSubscribe, addr("192.168.12.155"), 100, yes);
	EXPECT_TRUE(out.ok.empty());
}

TEST(PnpResponder, RetransmitGetsTheSameTagAndNoSecondNotify)
{
	Bench b(PnpResponder::Mode::Provision);
	const auto first = b.feed(kSnomSubscribe, "192.168.12.155", 100);
	ASSERT_FALSE(first.notify.empty());
	const std::string ok1(first.ok);
	const auto again = b.feed(kSnomSubscribe, "192.168.12.155", 101);
	EXPECT_EQ(std::string(again.ok), ok1);       // same To tag: one dialog
	EXPECT_TRUE(again.notify.empty());            // cooldown
	const auto later = b.feed(kSnomSubscribe, "192.168.12.155", 101 + PnpResponder::kNotifyCooldownSeconds);
	EXPECT_FALSE(later.notify.empty());
}

TEST(PnpResponder, RepliesAreRateLimited)
{
	Bench b(PnpResponder::Mode::Provision);
	int answered = 0;
	for (int i = 0; i < 10; ++i)
	{
		if (!b.feed(kSnomSubscribe, "192.168.12.155", 100).ok.empty()) ++answered;
	}
	EXPECT_EQ(answered, PnpResponder::kBurst);
	EXPECT_FALSE(b.feed(kSnomSubscribe, "192.168.12.155", 100 + PnpResponder::kRefillSeconds).ok.empty());
}

TEST(PnpResponder, TableIsBoundedAndForgetsTheLeastRecentlySeen)
{
	Bench b(PnpResponder::Mode::Discover);
	for (uint32_t i = 0; i < PnpResponder::kMaxDevices + 3; ++i)
	{
		char mac[13];
		std::snprintf(mac, sizeof(mac), "0004130000%02x", i);
		std::string raw = replace(kSnomSubscribe, "From: <sip:MAC%3a0004132E08B4@", std::string("From: <sip:MAC%3a") + mac + "@");
		b.feed(raw, "192.168.12.155", 100 + i);
	}
	EXPECT_EQ(b.count(), PnpResponder::kMaxDevices);
	bool oldestKept = false;
	b.r.forEachDevice([&](const PnpResponder::Device& d) {
		if (std::string(d.id.mac.data()) == "000413000000") oldestKept = true;
	});
	EXPECT_FALSE(oldestKept);
}

TEST(PnpResponder, CountersSayWhyNothingWasHeard)
{
	Bench b(PnpResponder::Mode::Provision);
	b.feed(kSnomSubscribe, "10.9.9.9", 100);                       // off subnet
	b.feed("OPTIONS sip:x SIP/2.0\r\n\r\n", "192.168.12.155", 100);  // not PnP
	b.feed(kSnomSubscribe, "192.168.12.155", 100);                 // answered
	const PnpResponder::Counters c = b.r.counters();
	EXPECT_EQ(c.datagrams, 3u);
	EXPECT_EQ(c.offSubnet, 1u);
	EXPECT_EQ(c.notPnp, 1u);
	EXPECT_EQ(c.answered, 1u);
	EXPECT_FALSE(b.r.listening());
	b.r.setSocketState(false, 98);
	EXPECT_EQ(b.r.socketErrno(), 98);
	EXPECT_EQ(b.r.netmask(), ipOf("255.255.255.0"));
}

TEST(PnpResponder, ModeNamesRoundTripAndStoredBytesDecodeSafely)
{
	for (auto m : {PnpResponder::Mode::Off, PnpResponder::Mode::Discover, PnpResponder::Mode::Provision})
	{
		PnpResponder::Mode back = PnpResponder::Mode::Off;
		ASSERT_TRUE(PnpResponder::parseMode(PnpResponder::modeName(m), back));
		EXPECT_EQ(back, m);
		EXPECT_EQ(PnpResponder::decodeStored(static_cast<uint8_t>(m)), m);
	}
	PnpResponder::Mode m = PnpResponder::Mode::Provision;
	EXPECT_FALSE(PnpResponder::parseMode("on", m));
	EXPECT_EQ(PnpResponder::decodeStored(7), PnpResponder::Mode::Off);
}

TEST(PnpResponder, DatagramPathAllocatesNothing)
{
	Bench b(PnpResponder::Mode::Provision);
	b.feed(kSnomSubscribe, "192.168.12.155", 100);   // warm-up
	const std::string other = replace(kSnomSubscribe, "Call-ID: 3c26700857f2", "Call-ID: 99");
	const sockaddr_in src = addr("192.168.12.156");
	auto yes = [](std::string_view) { return true; };
	AllocGuard g;
	const auto r = b.r.onDatagram(other, src, 200, yes);
	EXPECT_EQ(g.delta(), 0u);
	EXPECT_FALSE(r.notify.empty());
}

// ── snom renderer + route shape ──────────────────────────────────────────────

TEST(SnomProvisioning, RendersLineOneForPocketDial)
{
	const std::string cfg = provisioning::snomConfigFor("1001", "192.168.12.195", 5060, false);
	ASSERT_FALSE(cfg.empty());
	EXPECT_EQ(cfg.rfind("<?xml version=\"1.0\" encoding=\"utf-8\"?>", 0), 0u);
	EXPECT_NE(cfg.find("<user_name idx=\"1\" perm=\"RW\">1001</user_name>"), std::string::npos);
	EXPECT_NE(cfg.find("<user_host idx=\"1\" perm=\"RW\">192.168.12.195</user_host>"), std::string::npos);
	EXPECT_NE(cfg.find("<codec_priority_list idx=\"1\" perm=\"RW\">pcmu,pcma,telephone-event</codec_priority_list>"),
		std::string::npos);
	EXPECT_NE(cfg.find("<user_srtp idx=\"1\" perm=\"RW\">off</user_srtp>"), std::string::npos);
	EXPECT_EQ(cfg.find("setting_server"), std::string::npos);
	EXPECT_EQ(cfg.find("password pocket-dial cannot"), std::string::npos);
	EXPECT_NE(provisioning::snomConfigFor("1001", "192.168.12.195", 5060, true).find("password pocket-dial cannot"),
		std::string::npos);
	EXPECT_NE(provisioning::snomConfigFor("1001", "10.0.0.1", 5070, false).find(">10.0.0.1:5070<"), std::string::npos);
}

TEST(SnomProvisioning, RefusesCrLfAndEscapesXml)
{
	EXPECT_TRUE(provisioning::snomConfigFor("10\r\n01", "192.168.12.195", 5060, false).empty());
	EXPECT_NE(provisioning::snomConfigFor("1&2", "192.168.12.195", 5060, false).find(">1&amp;2<"), std::string::npos);
}

TEST(SnomProvisioning, UserAgentPicksSnom)
{
	EXPECT_EQ(provisioning::detectVendorFromUserAgent("snom370-SIP 8.7.5.48"), provisioning::Vendor::Snom);
	EXPECT_EQ(provisioning::detectVendorFromUserAgent("Mozilla/4.0 (compatible; snom370-SIP 8.7.5.48 1.1.3-u 0004132E08B4)"),
		provisioning::Vendor::Snom);
	EXPECT_NE(provisioning::renderProvisioningConfigForUserAgent("snomD785/10.1", "1001", "192.168.12.195", 5060, false)
		.find("<phone-settings"), std::string::npos);
}

TEST(SnomProvisioning, PathShapeAcceptsEitherCaseAndKeysLowercase)
{
	std::string key;
	EXPECT_EQ(HttpServer::parseProvisioningPath("/config/snom0004132e08b4.xml", key), HttpServer::ProvisioningPathType::Snom);
	EXPECT_EQ(key, "0004132e08b4");
	EXPECT_EQ(HttpServer::parseProvisioningPath("/config/snom0004132E08B4.xml", key), HttpServer::ProvisioningPathType::Snom);
	EXPECT_EQ(key, "0004132e08b4");
	EXPECT_FALSE(HttpServer::isProvisioningConfigPath("/config/snom0004132e08b.xml"));
	EXPECT_FALSE(HttpServer::isProvisioningConfigPath("/config/snom0004132e08bz.xml"));
	EXPECT_FALSE(HttpServer::isProvisioningConfigPath("/config/snom0004132e08b4.cfg"));
	EXPECT_FALSE(HttpServer::isProvisioningConfigPath("/config/SNOM0004132e08b4.xml"));
}
