// Tests for zero-touch phone auto-provisioning (Issue #35): the pure Yealink
// config builder (src/SIP/ProvisioningConfig.hpp) and the HttpServer/
// RequestsHandler wiring around it.

#include <gtest/gtest.h>

#include "HttpServer.hpp"
#include "ProvisioningConfig.hpp"
#include "RequestsHandler.hpp"

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

TEST(ProvisioningConfig, OpenModeConfigHasNoAuthWarningAndBlankPassword)
{
	std::string cfg = provisioning::yealinkConfigFor("101", "192.168.4.1", 5060,
		/*authRequired=*/false);

	EXPECT_NE(cfg.find("account.1.user_name = 101"), std::string::npos) << cfg;
	EXPECT_NE(cfg.find("account.1.sip_server.1.address = 192.168.4.1"), std::string::npos) << cfg;
	EXPECT_NE(cfg.find("account.1.sip_server.1.port = 5060"), std::string::npos) << cfg;
	EXPECT_NE(cfg.find("account.1.password = \r\n"), std::string::npos)
		<< "password field must be present but blank" << cfg;
	EXPECT_EQ(cfg.find("requires a SIP password"), std::string::npos)
		<< "Open/Learn-mode config should not carry the auth warning";
	// Only the two codecs the server actually enforces (enforceG711).
	EXPECT_NE(cfg.find("PCMU"), std::string::npos) << cfg;
	EXPECT_NE(cfg.find("PCMA"), std::string::npos) << cfg;
	EXPECT_EQ(cfg.find("G729"), std::string::npos) << cfg;
}

TEST(ProvisioningConfig, SecureModeConfigWarnsPasswordMustBeSetByHand)
{
	std::string cfg = provisioning::yealinkConfigFor("102", "192.168.4.1", 5060,
		/*authRequired=*/true);

	EXPECT_NE(cfg.find("requires a SIP password"), std::string::npos) << cfg;
	EXPECT_NE(cfg.find("account.1.password = \r\n"), std::string::npos)
		<< "still blank -- the server never has the plaintext to give out" << cfg;
}

// ── HttpServer::isProvisioningConfigPath (pure path-shape check) ───────────────

TEST(ProvisioningConfig, PathShapeAcceptsExactly12LowercaseHexChars)
{
	EXPECT_TRUE(HttpServer::isProvisioningConfigPath("/config/805ec079c37f.cfg"));
	EXPECT_TRUE(HttpServer::isProvisioningConfigPath("/config/0000000000ff.cfg"));
}

TEST(ProvisioningConfig, PathShapeRejectsWrongLengthOrCharsOrMissingPieces)
{
	EXPECT_FALSE(HttpServer::isProvisioningConfigPath("/config/805ec079c37.cfg"));    // 11 hex
	EXPECT_FALSE(HttpServer::isProvisioningConfigPath("/config/805ec079c37ff.cfg"));  // 13 hex
	EXPECT_FALSE(HttpServer::isProvisioningConfigPath("/config/805EC079C37F.cfg"));   // uppercase
	EXPECT_FALSE(HttpServer::isProvisioningConfigPath("/config/805ec079c37g.cfg"));   // non-hex 'g'
	EXPECT_FALSE(HttpServer::isProvisioningConfigPath("/config/805ec079c37f.txt"));   // wrong suffix
	EXPECT_FALSE(HttpServer::isProvisioningConfigPath("/configs/805ec079c37f.cfg"));  // wrong prefix
	EXPECT_FALSE(HttpServer::isProvisioningConfigPath("/config/805ec079c37f"));       // no suffix
	EXPECT_FALSE(HttpServer::isProvisioningConfigPath("/config/../../etc/passwd"));   // traversal attempt
}

TEST(ProvisioningConfig, MultiVendorPathShapesAccepted)
{
	// Grandstream cfg<mac>.xml
	EXPECT_TRUE(HttpServer::isProvisioningConfigPath("/config/cfg805ec079c37f.xml"));
	// Polycom per-phone <mac>-phone.cfg
	EXPECT_TRUE(HttpServer::isProvisioningConfigPath("/config/805ec079c37f-phone.cfg"));
	// Polycom master 000000000000.cfg
	EXPECT_TRUE(HttpServer::isProvisioningConfigPath("/config/000000000000.cfg"));
	// Cisco SPA macro spa<mac>.cfg
	EXPECT_TRUE(HttpServer::isProvisioningConfigPath("/config/spa805ec079c37f.cfg"));
	// Cisco SPA model spa<model>.cfg
	EXPECT_TRUE(HttpServer::isProvisioningConfigPath("/config/spa504g.cfg"));
	EXPECT_TRUE(HttpServer::isProvisioningConfigPath("/config/spa112.cfg"));
	EXPECT_TRUE(HttpServer::isProvisioningConfigPath("/config/spa303.cfg"));
}

TEST(ProvisioningConfig, MultiVendorPathShapesRejectedWhenMalformed)
{
	// Grandstream malformed
	EXPECT_FALSE(HttpServer::isProvisioningConfigPath("/config/cfg805ec079c37.xml"));   // 11 hex
	EXPECT_FALSE(HttpServer::isProvisioningConfigPath("/config/cfg805EC079C37F.xml"));  // uppercase
	EXPECT_FALSE(HttpServer::isProvisioningConfigPath("/config/cfg805ec079c37f.cfg"));  // wrong suffix
	// Polycom malformed
	EXPECT_FALSE(HttpServer::isProvisioningConfigPath("/config/805ec079c37-phone.cfg"));  // 11 hex
	EXPECT_FALSE(HttpServer::isProvisioningConfigPath("/config/805EC079C37F-phone.cfg")); // uppercase
	EXPECT_FALSE(HttpServer::isProvisioningConfigPath("/config/805ec079c37f-phone.xml")); // wrong suffix
	// Cisco SPA malformed
	EXPECT_FALSE(HttpServer::isProvisioningConfigPath("/config/spa805ec079c37.cfg"));   // 11 hex
	EXPECT_FALSE(HttpServer::isProvisioningConfigPath("/config/spa.cfg"));              // empty model
	EXPECT_FALSE(HttpServer::isProvisioningConfigPath("/config/spa504g.xml"));          // wrong suffix
	EXPECT_FALSE(HttpServer::isProvisioningConfigPath("/config/spa504g/cfg"));          // traversal/slash
}

TEST(ProvisioningConfig, ParseProvisioningPathExtractsCorrectKeyAndType)
{
	std::string key;
	EXPECT_EQ(HttpServer::parseProvisioningPath("/config/805ec079c37f.cfg", key),
		HttpServer::ProvisioningPathType::Yealink);
	EXPECT_EQ(key, "805ec079c37f");

	EXPECT_EQ(HttpServer::parseProvisioningPath("/config/cfg805ec079c37f.xml", key),
		HttpServer::ProvisioningPathType::Grandstream);
	EXPECT_EQ(key, "805ec079c37f");

	EXPECT_EQ(HttpServer::parseProvisioningPath("/config/805ec079c37f-phone.cfg", key),
		HttpServer::ProvisioningPathType::PolycomPhone);
	EXPECT_EQ(key, "805ec079c37f");

	EXPECT_EQ(HttpServer::parseProvisioningPath("/config/000000000000.cfg", key),
		HttpServer::ProvisioningPathType::PolycomMaster);
	EXPECT_TRUE(key.empty());

	EXPECT_EQ(HttpServer::parseProvisioningPath("/config/spa805ec079c37f.cfg", key),
		HttpServer::ProvisioningPathType::CiscoSpaMac);
	EXPECT_EQ(key, "805ec079c37f");

	EXPECT_EQ(HttpServer::parseProvisioningPath("/config/spa504g.cfg", key),
		HttpServer::ProvisioningPathType::CiscoSpaModel);
	EXPECT_EQ(key, "504g");
}

// ── RequestsHandler::findProvisioningInfo ───────────────────────────────────────

TEST(ProvisioningConfig, FindProvisioningInfoReturnsNulloptForUnknownMac)
{
	RequestsHandler handler("192.168.4.1", 5060,
		[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});
	EXPECT_FALSE(handler.findProvisioningInfo("805ec079c37f").has_value());
}

// ── Config-line injection via the extension (Issue #107) ──────────────────────
//
// yealinkConfigFor() interpolates the extension into `key = value\r\n` lines. An
// extension carrying a CR or LF could therefore append config keys the admin
// never wrote -- `account.1.password` being the interesting one. onRegister()
// gates every adopted extension through isValidAor(), whose charset excludes
// CR/LF, so this is not reachable today; these pin the format-level backstop so
// it stays unreachable if a future caller feeds the builder from somewhere else.

TEST(ProvisioningConfig, BuilderRefusesExtensionCarryingCrlfInjection)
{
	std::string cfg = provisioning::yealinkConfigFor(
		"101\r\naccount.1.password = hunter2", "192.168.4.1", 5060,
		/*authRequired=*/false);

	EXPECT_TRUE(cfg.empty())
		<< "a CRLF-bearing extension must produce no config at all, rather than "
		   "one carrying the injected line: " << cfg;
}

TEST(ProvisioningConfig, BuilderRefusesBareCrAndBareLf)
{
	EXPECT_TRUE(provisioning::yealinkConfigFor("101\naccount.1.password = x",
		"192.168.4.1", 5060, false).empty()) << "bare LF";
	EXPECT_TRUE(provisioning::yealinkConfigFor("101\raccount.1.password = x",
		"192.168.4.1", 5060, false).empty()) << "bare CR";
	// Trailing, not just embedded -- a lone terminator still opens the next line.
	EXPECT_TRUE(provisioning::yealinkConfigFor("101\r\n",
		"192.168.4.1", 5060, false).empty()) << "trailing CRLF";
}

TEST(ProvisioningConfig, BuilderStillAcceptsTheRestOfTheAorCharset)
{
	// The guard rejects CR/LF only. Star codes, '+', and the RFC 3261 user-part
	// punctuation isValidAor() allows are legitimate extensions and must still
	// provision -- a stricter [0-9A-Za-z] strip would silently mangle these.
	for (const char* ext : {"*55", "+15551234", "1_0.1-a", "#77"})
	{
		std::string cfg = provisioning::yealinkConfigFor(ext, "192.168.4.1", 5060,
			/*authRequired=*/false);
		EXPECT_NE(cfg.find(std::string("account.1.user_name = ") + ext), std::string::npos)
			<< "extension '" << ext << "' should provision unchanged: " << cfg;
	}
}

// ── Multi-vendor renderers (Issue #177) ─────────────────────────────────────
//
// Fixture device record shared by every test below: extension "101",
// registrar "192.168.4.1":5060, matching the Yealink tests above.

TEST(ProvisioningConfig, GrandstreamConfigForProducesConfigVersion1RootAndAccountFields)
{
	std::string cfg = provisioning::grandstreamConfigFor("101", "192.168.4.1", 5060,
		/*authRequired=*/false);

	EXPECT_NE(cfg.find("<gs_provision version=\"1\">"), std::string::npos) << cfg;
	EXPECT_NE(cfg.find("<config version=\"1\">"), std::string::npos) << cfg;
	EXPECT_NE(cfg.find("</config>"), std::string::npos) << cfg;
	EXPECT_NE(cfg.find("</gs_provision>"), std::string::npos) << cfg;
	EXPECT_NE(cfg.find("<P35>101</P35>"), std::string::npos) << "SIP User ID: " << cfg;
	EXPECT_NE(cfg.find("<P47>192.168.4.1</P47>"), std::string::npos)
		<< "SIP Server, default port 5060 omitted: " << cfg;
	EXPECT_NE(cfg.find("<P36>101</P36>"), std::string::npos) << "SIP Authenticate ID: " << cfg;
	EXPECT_NE(cfg.find("<P34></P34>"), std::string::npos)
		<< "password field (P34) must be present but blank: " << cfg;
	EXPECT_EQ(cfg.find("<P34>101</P34>"), std::string::npos)
		<< "the extension must never land in the PASSWORD element (PR #224 review): " << cfg;
	EXPECT_EQ(cfg.find("requires a SIP password"), std::string::npos)
		<< "Open/Learn-mode config should not carry the auth warning";
}

TEST(ProvisioningConfig, GrandstreamConfigForFoldsNonDefaultPortIntoServerField)
{
	// Grandstream has no separate SIP-port P-number this file could confirm
	// (see docs/PROVISIONING.md §2.5) -- a non-default port folds into P47 as
	// "ip:port", matching the vendor's own "address and port together" field
	// description.
	std::string cfg = provisioning::grandstreamConfigFor("101", "192.168.4.1", 5080,
		/*authRequired=*/false);

	EXPECT_NE(cfg.find("<P47>192.168.4.1:5080</P47>"), std::string::npos) << cfg;
}

TEST(ProvisioningConfig, GrandstreamConfigForWarnsPasswordMustBeSetByHandWhenAuthRequired)
{
	std::string cfg = provisioning::grandstreamConfigFor("102", "192.168.4.1", 5060,
		/*authRequired=*/true);

	EXPECT_NE(cfg.find("requires a SIP password"), std::string::npos) << cfg;
	EXPECT_NE(cfg.find("<P34></P34>"), std::string::npos)
		<< "still blank -- the server never has the plaintext to give out" << cfg;
}

TEST(ProvisioningConfig, GrandstreamConfigForEscapesXmlSpecialCharsInExtension)
{
	// '&' is NOT reachable through the live route today (isValidAor() admits
	// only alnum + `.-_+*#`); this pins the defence-in-depth escaping of a pure
	// function that a less-filtered caller could be wired to later. Unescaped,
	// "1&2" inside <P35> would stop being valid XML content at the '&'.
	std::string cfg = provisioning::grandstreamConfigFor("1&2", "192.168.4.1", 5060,
		/*authRequired=*/false);

	EXPECT_NE(cfg.find("<P35>1&amp;2</P35>"), std::string::npos) << cfg;
	EXPECT_EQ(cfg.find("1&2"), std::string::npos)
		<< "the raw, unescaped extension must not appear anywhere: " << cfg;
}

TEST(ProvisioningConfig, GrandstreamConfigForBlocksCrlfInjection)
{
	EXPECT_TRUE(provisioning::grandstreamConfigFor("101\r\n<P36>hunter2</P36>",
		"192.168.4.1", 5060, false).empty());
	EXPECT_TRUE(provisioning::grandstreamConfigFor("101\naccount = x",
		"192.168.4.1", 5060, false).empty()) << "bare LF";
	EXPECT_TRUE(provisioning::grandstreamConfigFor("101\raccount = x",
		"192.168.4.1", 5060, false).empty()) << "bare CR";
}

TEST(ProvisioningConfig, PolycomPhoneConfigForProducesRegAttributesForKnownDevice)
{
	std::string cfg = provisioning::polycomPhoneConfigFor("101", "192.168.4.1", 5060,
		/*authRequired=*/false);

	EXPECT_NE(cfg.find("<phone1>"), std::string::npos) << cfg;
	EXPECT_NE(cfg.find("</phone1>"), std::string::npos) << cfg;
	EXPECT_NE(cfg.find("reg.1.address=\"101\""), std::string::npos) << cfg;
	EXPECT_NE(cfg.find("reg.1.auth.userId=\"101\""), std::string::npos) << cfg;
	EXPECT_NE(cfg.find("reg.1.server.1.address=\"192.168.4.1\""), std::string::npos) << cfg;
	EXPECT_NE(cfg.find("reg.1.server.1.port=\"5060\""), std::string::npos) << cfg;
	EXPECT_NE(cfg.find("reg.1.auth.password=\"\""), std::string::npos)
		<< "password attribute must be present but blank: " << cfg;
	EXPECT_EQ(cfg.find("requires a SIP password"), std::string::npos)
		<< "Open/Learn-mode config should not carry the auth warning";
}

TEST(ProvisioningConfig, PolycomPhoneConfigForWarnsPasswordMustBeSetByHandWhenAuthRequired)
{
	std::string cfg = provisioning::polycomPhoneConfigFor("102", "192.168.4.1", 5060,
		/*authRequired=*/true);

	EXPECT_NE(cfg.find("requires a SIP password"), std::string::npos) << cfg;
	EXPECT_NE(cfg.find("reg.1.auth.password=\"\""), std::string::npos)
		<< "still blank -- the server never has the plaintext to give out" << cfg;
}

TEST(ProvisioningConfig, PolycomPhoneConfigForEscapesXmlSpecialCharsInExtension)
{
	// Polycom's fields are XML ATTRIBUTE values, so a bare '"' would be worse
	// than Grandstream/Cisco's element-content case -- it would terminate the
	// attribute early rather than just breaking well-formedness downstream.
	std::string cfg = provisioning::polycomPhoneConfigFor("1&2", "192.168.4.1", 5060,
		/*authRequired=*/false);

	EXPECT_NE(cfg.find("reg.1.address=\"1&amp;2\""), std::string::npos) << cfg;
	EXPECT_EQ(cfg.find("1&2"), std::string::npos)
		<< "the raw, unescaped extension must not appear anywhere: " << cfg;
}

TEST(ProvisioningConfig, PolycomPhoneConfigForBlocksCrlfInjection)
{
	EXPECT_TRUE(provisioning::polycomPhoneConfigFor("101\r\nreg.2.address=\"666\"",
		"192.168.4.1", 5060, false).empty());
	EXPECT_TRUE(provisioning::polycomPhoneConfigFor("101\naddr", "192.168.4.1", 5060, false).empty())
		<< "bare LF";
	EXPECT_TRUE(provisioning::polycomPhoneConfigFor("101\raddr", "192.168.4.1", 5060, false).empty())
		<< "bare CR";
}

TEST(ProvisioningConfig, PolycomBaseConfigReferencesPerPhoneFileAndCarriesNoDeviceData)
{
	// Called with no arguments: the master file is the same for every phone.
	std::string cfg = provisioning::polycomBaseConfigFor();

	EXPECT_NE(cfg.find("<APPLICATION"), std::string::npos) << cfg;
	EXPECT_NE(cfg.find("CONFIG_FILES=\"$MACADDRESS-phone.cfg\""), std::string::npos)
		<< "must point at the per-phone file polycomPhoneConfigFor() renders: " << cfg;
	EXPECT_FALSE(cfg.empty());
}

TEST(ProvisioningConfig, CiscoSpaConfigForProducesFlatProfileLineFields)
{
	std::string cfg = provisioning::ciscoSpaConfigFor("101", "192.168.4.1", 5060,
		/*authRequired=*/false);

	EXPECT_NE(cfg.find("<flat-profile>"), std::string::npos) << cfg;
	EXPECT_NE(cfg.find("</flat-profile>"), std::string::npos) << cfg;
	EXPECT_NE(cfg.find("<Line_Enable_1_>Yes</Line_Enable_1_>"), std::string::npos) << cfg;
	EXPECT_NE(cfg.find("<User_ID_1_>101</User_ID_1_>"), std::string::npos) << cfg;
	EXPECT_NE(cfg.find("<Proxy_1_>192.168.4.1</Proxy_1_>"), std::string::npos)
		<< "Proxy, default port 5060 omitted: " << cfg;
	EXPECT_NE(cfg.find("<Preferred_Codec_1_>G711u</Preferred_Codec_1_>"), std::string::npos) << cfg;
	EXPECT_NE(cfg.find("<Second_Preferred_Codec_1_>G711a</Second_Preferred_Codec_1_>"),
		std::string::npos) << cfg;
	EXPECT_NE(cfg.find("<Password_1_></Password_1_>"), std::string::npos)
		<< "password field must be present but blank: " << cfg;
	EXPECT_EQ(cfg.find("requires a SIP password"), std::string::npos)
		<< "Open/Learn-mode config should not carry the auth warning";
}

TEST(ProvisioningConfig, CiscoSpaConfigForFoldsNonDefaultPortIntoProxyField)
{
	// SPA firmware has no separate proxy-port tag (see docs/PROVISIONING.md
	// §2.5) -- a non-default port folds into Proxy_1_ as "ip:port", matching
	// the vendor's own provisioning guide example ("192.168.2.100:6060").
	std::string cfg = provisioning::ciscoSpaConfigFor("101", "192.168.4.1", 5080,
		/*authRequired=*/false);

	EXPECT_NE(cfg.find("<Proxy_1_>192.168.4.1:5080</Proxy_1_>"), std::string::npos) << cfg;
}

TEST(ProvisioningConfig, CiscoSpaConfigForWarnsPasswordMustBeSetByHandWhenAuthRequired)
{
	std::string cfg = provisioning::ciscoSpaConfigFor("102", "192.168.4.1", 5060,
		/*authRequired=*/true);

	EXPECT_NE(cfg.find("requires a SIP password"), std::string::npos) << cfg;
	EXPECT_NE(cfg.find("<Password_1_></Password_1_>"), std::string::npos)
		<< "still blank -- the server never has the plaintext to give out" << cfg;
}

TEST(ProvisioningConfig, CiscoSpaConfigForEscapesXmlSpecialCharsInExtension)
{
	std::string cfg = provisioning::ciscoSpaConfigFor("1&2", "192.168.4.1", 5060,
		/*authRequired=*/false);

	EXPECT_NE(cfg.find("<User_ID_1_>1&amp;2</User_ID_1_>"), std::string::npos) << cfg;
	EXPECT_EQ(cfg.find("1&2"), std::string::npos)
		<< "the raw, unescaped extension must not appear anywhere: " << cfg;
}

TEST(ProvisioningConfig, CiscoSpaConfigForBlocksCrlfInjection)
{
	EXPECT_TRUE(provisioning::ciscoSpaConfigFor("101\r\n<Register_1_>No</Register_1_>",
		"192.168.4.1", 5060, false).empty());
	EXPECT_TRUE(provisioning::ciscoSpaConfigFor("101\nx", "192.168.4.1", 5060, false).empty())
		<< "bare LF";
	EXPECT_TRUE(provisioning::ciscoSpaConfigFor("101\rx", "192.168.4.1", 5060, false).empty())
		<< "bare CR";
}

// ── User-Agent vendor detection + dispatch (Issue #177) ─────────────────────

TEST(ProvisioningConfig, DetectVendorFromUserAgentRecognizesEachVendor)
{
	EXPECT_EQ(provisioning::detectVendorFromUserAgent("Yealink SIP-T46S 66.86.0.15"),
		provisioning::Vendor::Yealink);
	EXPECT_EQ(provisioning::detectVendorFromUserAgent("Grandstream GXP2170 1.0.9.60"),
		provisioning::Vendor::Grandstream);
	EXPECT_EQ(provisioning::detectVendorFromUserAgent("PolycomVVX-VVX411-UA/5.9.3.0416"),
		provisioning::Vendor::Polycom);
	EXPECT_EQ(provisioning::detectVendorFromUserAgent("Cisco/SPA504G-7.6.2b"),
		provisioning::Vendor::CiscoSpa);
	EXPECT_EQ(provisioning::detectVendorFromUserAgent("Linksys/SPA942-5.1.8"),
		provisioning::Vendor::CiscoSpa);
	EXPECT_EQ(provisioning::detectVendorFromUserAgent("Sipura/SPA-2000-3.1.15"),
		provisioning::Vendor::CiscoSpa);
}

TEST(ProvisioningConfig, DetectVendorFromUserAgentIsCaseInsensitive)
{
	EXPECT_EQ(provisioning::detectVendorFromUserAgent("GRANDSTREAM GXP2170"),
		provisioning::Vendor::Grandstream);
	EXPECT_EQ(provisioning::detectVendorFromUserAgent("polycomvvx-vvx411-ua/5.9"),
		provisioning::Vendor::Polycom);
	EXPECT_EQ(provisioning::detectVendorFromUserAgent("CISCO/SPA504G"),
		provisioning::Vendor::CiscoSpa);
}

TEST(ProvisioningConfig, DetectVendorFromUserAgentFallsBackToYealinkOnUnrecognizedOrEmpty)
{
	EXPECT_EQ(provisioning::detectVendorFromUserAgent("SomeOtherPhone/1.0"),
		provisioning::Vendor::Yealink);
	EXPECT_EQ(provisioning::detectVendorFromUserAgent(""), provisioning::Vendor::Yealink);
	EXPECT_EQ(provisioning::detectVendorFromUserAgent("Mozilla/5.0 (curious browser)"),
		provisioning::Vendor::Yealink);
}

TEST(ProvisioningConfig, DetectVendorFromUserAgentRequiresSpaTokenForCiscoFamily)
{
	// A plain Cisco IP Phone (the 78xx/88xx CUCM-managed line, not the SPA/MPP
	// small-business family) must NOT be misdetected into the Cisco SPA
	// flat-profile renderer just because its UA also contains "Cisco".
	EXPECT_EQ(provisioning::detectVendorFromUserAgent("Cisco/IP Phone 8841"),
		provisioning::Vendor::Yealink);
}

TEST(ProvisioningConfig, RenderProvisioningConfigForUserAgentDispatchesToRightRendererPerVendor)
{
	struct Case { const char* userAgent; const char* mustContain; };
	const Case cases[] = {
		{"Yealink SIP-T46S 66.86.0.15", "#!version:1.0.0.1"},
		{"Grandstream GXP2170 1.0.9.60", "<gs_provision version=\"1\">"},
		{"PolycomVVX-VVX411-UA/5.9.3.0416", "<phone1>"},
		{"Cisco/SPA504G-7.6.2b", "<flat-profile>"},
		{"SomeOtherPhone/1.0", "#!version:1.0.0.1"},  // fallback
	};
	for (const auto& c : cases)
	{
		std::string cfg = provisioning::renderProvisioningConfigForUserAgent(
			c.userAgent, "101", "192.168.4.1", 5060, /*authRequired=*/false);
		EXPECT_NE(cfg.find(c.mustContain), std::string::npos)
			<< "UA '" << c.userAgent << "' should render a config containing '"
			<< c.mustContain << "': " << cfg;
	}
}

// ── HTTP route integration tests (Issue #234) ───────────────────────────────
//
// Ports: this section owns 18170-18179. See CONTRIBUTING_FIRMWARE.md.

namespace
{
	int nextProvisioningPort()
	{
		static int port = 18170;
		return port++;
	}

	std::string httpGetWithUa(int port, const std::string& path, const std::string& userAgent = "")
	{
#if defined(_WIN32) || defined(_WIN64)
		SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
		if (s == INVALID_SOCKET) return "";
#else
		int s = socket(AF_INET, SOCK_STREAM, 0);
		if (s < 0) return "";
#endif
		sockaddr_in addr{};
		addr.sin_family = AF_INET;
		addr.sin_port = htons(static_cast<uint16_t>(port));
		inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
		if (connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0)
		{
#if defined(_WIN32) || defined(_WIN64)
			closesocket(s);
#else
			close(s);
#endif
			return "";
		}

		std::string req = "GET " + path + " HTTP/1.1\r\nHost: 127.0.0.1\r\n";
		if (!userAgent.empty())
		{
			req += "User-Agent: " + userAgent + "\r\n";
		}
		req += "Connection: close\r\n\r\n";
		send(s, req.c_str(), static_cast<int>(req.size()), 0);

		std::string resp;
		char buf[512];
		int n;
		while ((n = recv(s, buf, sizeof(buf), 0)) > 0)
		{
			resp.append(buf, static_cast<size_t>(n));
		}
#if defined(_WIN32) || defined(_WIN64)
		closesocket(s);
#else
		close(s);
#endif
		return resp;
	}
}

TEST(ProvisioningConfig, HttpRouteServesPolycomMasterWithoutAdoptedDevice)
{
	int port = nextProvisioningPort();
	RequestsHandler handler("127.0.0.1", 5060,
		[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});
	HttpServer server("127.0.0.1", port, &handler);
	server.start();

	std::string resp = httpGetWithUa(port, "/config/000000000000.cfg");
	EXPECT_NE(resp.find("HTTP/1.1 200 OK"), std::string::npos) << resp;
	EXPECT_NE(resp.find("Content-Type: application/xml"), std::string::npos) << resp;
	EXPECT_NE(resp.find("<APPLICATION CONFIG_FILES="), std::string::npos) << resp;
}

TEST(ProvisioningConfig, HttpRouteDispatchesByPathShape)
{
	int port = nextProvisioningPort();
	RequestsHandler handler("127.0.0.1", 5060,
		[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});
	handler.adoptDeviceForTest("805ec079c37f", "101");
	HttpServer server("127.0.0.1", port, &handler);
	server.start();

	// 1. Grandstream cfg<mac>.xml
	std::string gsResp = httpGetWithUa(port, "/config/cfg805ec079c37f.xml");
	EXPECT_NE(gsResp.find("HTTP/1.1 200 OK"), std::string::npos) << gsResp;
	EXPECT_NE(gsResp.find("Content-Type: application/xml"), std::string::npos) << gsResp;
	EXPECT_NE(gsResp.find("<gs_provision version=\"1\">"), std::string::npos) << gsResp;
	EXPECT_NE(gsResp.find("<P35>101</P35>"), std::string::npos) << gsResp;

	// 2. Polycom per-phone <mac>-phone.cfg
	std::string polyResp = httpGetWithUa(port, "/config/805ec079c37f-phone.cfg");
	EXPECT_NE(polyResp.find("HTTP/1.1 200 OK"), std::string::npos) << polyResp;
	EXPECT_NE(polyResp.find("Content-Type: application/xml"), std::string::npos) << polyResp;
	EXPECT_NE(polyResp.find("<phone1>"), std::string::npos) << polyResp;
	EXPECT_NE(polyResp.find("reg.1.address=\"101\""), std::string::npos) << polyResp;

	// 3. Cisco SPA macro-expanded spa<mac>.cfg
	std::string spaResp = httpGetWithUa(port, "/config/spa805ec079c37f.cfg");
	EXPECT_NE(spaResp.find("HTTP/1.1 200 OK"), std::string::npos) << spaResp;
	EXPECT_NE(spaResp.find("Content-Type: application/xml"), std::string::npos) << spaResp;
	EXPECT_NE(spaResp.find("<flat-profile>"), std::string::npos) << spaResp;
	EXPECT_NE(spaResp.find("<User_ID_1_>101</User_ID_1_>"), std::string::npos) << spaResp;

	// 4. Cisco SPA model bootstrap spa<model>.cfg
	std::string modelResp = httpGetWithUa(port, "/config/spa504g.cfg");
	EXPECT_NE(modelResp.find("HTTP/1.1 200 OK"), std::string::npos) << modelResp;
	EXPECT_NE(modelResp.find("Content-Type: application/xml"), std::string::npos) << modelResp;
	EXPECT_NE(modelResp.find("<Profile_Rule>http://"), std::string::npos) << modelResp;
	EXPECT_NE(modelResp.find("/config/spa$MA.cfg</Profile_Rule>"), std::string::npos) << modelResp;

	// 5. Yealink / default <mac>.cfg with no User-Agent
	std::string ylResp = httpGetWithUa(port, "/config/805ec079c37f.cfg");
	EXPECT_NE(ylResp.find("HTTP/1.1 200 OK"), std::string::npos) << ylResp;
	EXPECT_NE(ylResp.find("Content-Type: text/plain"), std::string::npos) << ylResp;
	EXPECT_NE(ylResp.find("#!version:1.0.0.1"), std::string::npos) << ylResp;
	EXPECT_NE(ylResp.find("account.1.user_name = 101"), std::string::npos) << ylResp;
}

TEST(ProvisioningConfig, HttpRouteDispatchesMacCfgByUserAgent)
{
	int port = nextProvisioningPort();
	RequestsHandler handler("127.0.0.1", 5060,
		[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});
	handler.adoptDeviceForTest("805ec079c37f", "101");
	HttpServer server("127.0.0.1", port, &handler);
	server.start();

	// Grandstream UA
	std::string gsResp = httpGetWithUa(port, "/config/805ec079c37f.cfg", "Grandstream GXP2170 1.0.9.60");
	EXPECT_NE(gsResp.find("HTTP/1.1 200 OK"), std::string::npos) << gsResp;
	EXPECT_NE(gsResp.find("Content-Type: application/xml"), std::string::npos) << gsResp;
	EXPECT_NE(gsResp.find("<gs_provision version=\"1\">"), std::string::npos) << gsResp;

	// Polycom UA
	std::string polyResp = httpGetWithUa(port, "/config/805ec079c37f.cfg", "PolycomVVX-VVX411-UA/5.9.3.0416");
	EXPECT_NE(polyResp.find("HTTP/1.1 200 OK"), std::string::npos) << polyResp;
	EXPECT_NE(polyResp.find("Content-Type: application/xml"), std::string::npos) << polyResp;
	EXPECT_NE(polyResp.find("<phone1>"), std::string::npos) << polyResp;

	// Cisco SPA UA
	std::string spaResp = httpGetWithUa(port, "/config/805ec079c37f.cfg", "Cisco/SPA504G-7.6.2b");
	EXPECT_NE(spaResp.find("HTTP/1.1 200 OK"), std::string::npos) << spaResp;
	EXPECT_NE(spaResp.find("Content-Type: application/xml"), std::string::npos) << spaResp;
	EXPECT_NE(spaResp.find("<flat-profile>"), std::string::npos) << spaResp;

	// Yealink UA
	std::string ylResp = httpGetWithUa(port, "/config/805ec079c37f.cfg", "Yealink SIP-T46S 66.86.0.15");
	EXPECT_NE(ylResp.find("HTTP/1.1 200 OK"), std::string::npos) << ylResp;
	EXPECT_NE(ylResp.find("Content-Type: text/plain"), std::string::npos) << ylResp;
	EXPECT_NE(ylResp.find("#!version:1.0.0.1"), std::string::npos) << ylResp;
}

TEST(ProvisioningConfig, HttpRouteReturns404ForUnknownMac)
{
	int port = nextProvisioningPort();
	RequestsHandler handler("127.0.0.1", 5060,
		[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});
	HttpServer server("127.0.0.1", port, &handler);
	server.start();

	std::string r1 = httpGetWithUa(port, "/config/112233445566.cfg");
	EXPECT_NE(r1.find("HTTP/1.1 404 Not Found"), std::string::npos) << r1;

	std::string r2 = httpGetWithUa(port, "/config/cfg112233445566.xml");
	EXPECT_NE(r2.find("HTTP/1.1 404 Not Found"), std::string::npos) << r2;

	std::string r3 = httpGetWithUa(port, "/config/112233445566-phone.cfg");
	EXPECT_NE(r3.find("HTTP/1.1 404 Not Found"), std::string::npos) << r3;

	std::string r4 = httpGetWithUa(port, "/config/spa112233445566.cfg");
	EXPECT_NE(r4.find("HTTP/1.1 404 Not Found"), std::string::npos) << r4;
}
