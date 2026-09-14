#ifndef PROVISIONING_CONFIG_HPP
#define PROVISIONING_CONFIG_HPP

// ProvisioningConfig.hpp — pure config-file builders for zero-touch phone
// auto-provisioning (Issue #35), served by GET /config/<mac>.cfg.
//
// Targets Yealink's plain-text auto-provisioning format (key = value, not
// XML) — the vendor pocket-dial already accommodates elsewhere in the
// codebase (the register-beep INVITE's Call-Info/Alert-Info/P-Auto-Answer
// headers exist specifically to make a Yealink auto-answer; see
// RegisterBeeper.cpp). Only PCMU/PCMA are offered: enforceG711() (see
// SipMessage) is the only codec path the server actually supports, so
// listing anything else would just be a codec the phone tries and the
// server never accepts.
//
// Not hardware-verified — there is no physical Yealink phone in this
// session — the key names and syntax below follow Yealink's long-stable,
// widely-documented auto-provisioning key set, but treat this as
// best-effort until confirmed against a real handset.
//
// Issue #177 adds three more vendor renderers (Grandstream, Polycom, Cisco
// SPA) below, plus detectVendorFromUserAgent() / renderProvisioningConfig
// ForUserAgent() to pick one. Same "best-effort, not hardware-verified"
// status as the Yealink renderer above -- see each renderer's own comment
// for how confident to be in its specific field names, since that varies
// per vendor (some were confirmed against a primary-source example, most
// were not). None of the three is wired into the live /config/<mac>.cfg
// route yet: HttpServer::HttpRequest (HttpServer.cpp/.hpp) does not capture
// the User-Agent header at all today, the route's path-shape check accepts
// only the Yealink-era <mac>.cfg filename, and Polycom's second (base) file
// has no route at all -- extending any of that is a separate, out-of-scope
// change for this file. See docs/PROVISIONING.md for the details and the
// concrete follow-up list.

#include <algorithm>
#include <cctype>
#include <string>

namespace provisioning
{
	// Shared CR/LF injection guard (Issue #107): every renderer below
	// interpolates the extension into a line- or attribute-oriented format
	// where a raw CR or LF could inject content nobody wrote -- a new config
	// line for Yealink/Grandstream, a new attribute for Polycom, a new element
	// for Cisco SPA. Callers hand over an AOR-validated extension already
	// (isValidAor()'s charset excludes CR/LF), so this is a format-level
	// backstop for the ones that forget, same rationale as yealinkConfigFor's
	// own original inline check, factored out so every renderer shares it.
	inline bool containsCrOrLf(const std::string& s)
	{
		return s.find('\r') != std::string::npos || s.find('\n') != std::string::npos;
	}

	// XML-escapes the five characters XML gives special meaning to element and
	// attribute content. The three new renderers below are all XML (Yealink's
	// key=value format is not); '&' is the one every renderer emits by feeding
	// the extension straight through, so left unescaped it would silently break
	// well-formedness for an extension like "1&2" -- isValidAor()'s charset is
	// wider than Yealink's format-level needs bargained for. '<' '>' are near
	// impossible via that charset but escaped anyway since a fully-quoted
	// implementation is easier to audit than a partially-quoted one; '"' '\''
	// exist for Polycom, whose fields are XML attribute values, not element
	// text.
	inline std::string xmlEscape(const std::string& in)
	{
		std::string out;
		out.reserve(in.size());
		for (char c : in)
		{
			switch (c)
			{
				case '&':  out += "&amp;";  break;
				case '<':  out += "&lt;";   break;
				case '>':  out += "&gt;";   break;
				case '"':  out += "&quot;"; break;
				case '\'': out += "&apos;"; break;
				default:   out += c;        break;
			}
		}
		return out;
	}

	// Renders "ip" alone when the port is pocket-dial's only supported SIP port
	// (5060 -- this codebase doesn't run the SIP listener anywhere else; see
	// §2.3 of docs/PROVISIONING.md), or "ip:port" otherwise. Grandstream and
	// Cisco SPA both fold server address and port into one field instead of
	// carrying a separate port parameter -- Cisco's own SPA100/200 provisioning
	// guide's example for that field is literally "192.168.2.100:6060". Polycom
	// and Yealink each have a real, separate port parameter and don't use this.
	inline std::string serverAddressFor(const std::string& serverIp, int serverPort)
	{
		if (serverPort == 5060) return serverIp;
		return serverIp + ":" + std::to_string(serverPort);
	}

	// One phone's Yealink auto-provisioning config. `authRequired` says whether
	// this device must present a SIP digest to register — Registrar::Mode::
	// Secure, or a Learn-mode device individually promoted via
	// Registrar::secure(). The password field is always left blank either
	// way: Registrar/SipSecretStore only ever store HA1 = MD5(ext:realm:
	// secret), a one-way hash, so the server never has the plaintext secret
	// to provision with even when one is required — only whoever originally
	// set it does. When `authRequired` is true the config carries a comment
	// flagging that the admin still has to enter the password on the handset
	// by hand; the generated config still provisions everything else
	// (server, port, line, codecs), which is the tedious part either way.
	inline std::string yealinkConfigFor(const std::string& extension,
		const std::string& serverIp, int serverPort, bool authRequired)
	{
		// Every value below lands in a `key = value\r\n` line, so a CR or LF in the
		// extension would inject config lines into the file the handset parses
		// (Issue #107). Callers hand over an AOR-validated extension -- this is the
		// format-level backstop for the ones that forget, and for future callers
		// wiring in less-trusted input. Only CR/LF is rejected, not the whole AOR
		// charset: '*55' and '+15551234' are legitimate extensions and provision fine.
		if (containsCrOrLf(extension))
		{
			return {};
		}

		std::string out;
		out.reserve(512);
		out += "#!version:1.0.0.1\r\n";
		out += "# Auto-generated by pocket-dial for extension " + extension + ". Issue #35.\r\n";
		if (authRequired)
		{
			out += "# This extension requires a SIP password pocket-dial cannot provision\r\n";
			out += "# automatically (only a one-way hash of it is stored server-side) --\r\n";
			out += "# set account.1.password by hand on this handset before it can register.\r\n";
		}
		out += "account.1.enable = 1\r\n";
		out += "account.1.label = " + extension + "\r\n";
		out += "account.1.display_name = " + extension + "\r\n";
		out += "account.1.auth_name = " + extension + "\r\n";
		out += "account.1.user_name = " + extension + "\r\n";
		out += "account.1.password = \r\n";
		out += "account.1.sip_server.1.address = " + serverIp + "\r\n";
		out += "account.1.sip_server.1.port = " + std::to_string(serverPort) + "\r\n";
		out += "account.1.sip_server.1.transport_type = 0\r\n";  // UDP
		out += "account.1.nat.udp_update_enable = 0\r\n";
		// PCMU (payload 0) then PCMA (payload 8) — the two enforceG711() keeps.
		out += "account.1.codec.1.enable = 1\r\n";
		out += "account.1.codec.1.payload_type = PCMU\r\n";
		out += "account.1.codec.1.priority = 1\r\n";
		out += "account.1.codec.2.enable = 1\r\n";
		out += "account.1.codec.2.payload_type = PCMA\r\n";
		out += "account.1.codec.2.priority = 2\r\n";
		return out;
	}

	// ── Grandstream (Issue #177) ────────────────────────────────────────────────
	//
	// Format: root <gs_provision version="1">, an optional <mac> element, and a
	// <config version="1"> wrapping one <PNNN>value</PNNN> element per parameter
	// -- this structure (including the element-per-parameter shape, not a
	// "PNNN = value" text-line shape) is confirmed against Grandstream's own
	// "SIP Device Provisioning Guide", whose own example is:
	//   <gs_provision version="1"><mac>000b82123456</mac>
	//    <config version="1"><P271>0</P271><P270>Account name</P270></config>
	//   </gs_provision>
	// That example is also the source for using P271 as the numeric Active flag
	// and P270 as the string account name/label below -- everything else
	// (P34/P35/P36/P47/P57/P58) is reconstructed from secondary references that
	// disagree with each other on which P-number means what (P-value
	// assignments are documented per device generation, not universally), so
	// treat those specifically as unverified best-effort -- confirm against the
	// target model's own P-Value guide before a real deployment. See
	// docs/PROVISIONING.md §2.5 for the two disagreeing sources.
	//
	// P47 folds in a non-default port as "ip:port" (serverAddressFor()) rather
	// than a separate port field: Grandstream's own SIP-Server field is
	// documented as taking "URL or IP address, and port" together, and there is
	// no reliably-sourced separate port P-number for this -- an earlier draft
	// used P40 ("Local SIP Port") for this, which is the PHONE's own listening
	// port, not the registrar's, and was wrong.
	inline std::string grandstreamConfigFor(const std::string& extension,
		const std::string& serverIp, int serverPort, bool authRequired)
	{
		if (containsCrOrLf(extension))
		{
			return {};
		}

		std::string ext = xmlEscape(extension);
		std::string out;
		out.reserve(1024);
		out += "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\r\n";
		out += "<gs_provision version=\"1\">\r\n";
		out += "<config version=\"1\">\r\n";
		// The extension is NOT interpolated into this comment (unlike Yealink's
		// text-format comment above): an XML comment body may not contain "--",
		// and the AOR charset that reaches here is not guaranteed to exclude a
		// literal hyphen pair, so echoing it here would be a second, harder-to-
		// guard injection surface for no functional benefit -- the extension is
		// already present, escaped, in the real P35/P34/P270 elements below.
		out += "<!-- Auto-generated by pocket-dial. Issues #35, #177. -->\r\n";
		if (authRequired)
		{
			out += "<!-- This extension requires a SIP password pocket-dial cannot provision   -->\r\n";
			out += "<!-- automatically (only a one-way hash of it is stored server-side), so    -->\r\n";
			out += "<!-- set the account password by hand on this handset before it registers.  -->\r\n";
		}
		out += "<P271>1</P271>\r\n";                                  // Account Active
		out += "<P270>" + ext + "</P270>\r\n";                        // Account Name / label
		out += "<P35>" + ext + "</P35>\r\n";                          // SIP User ID
		out += "<P34>" + ext + "</P34>\r\n";                          // SIP Authenticate ID
		out += "<P36></P36>\r\n";                                     // SIP Authenticate Password -- always blank, see yealinkConfigFor's rationale above (HA1-only storage)
		out += "<P47>" + serverAddressFor(serverIp, serverPort) + "</P47>\r\n";  // SIP Server[:port]
		// Preferred vocoder 1/2 -- 0=PCMU, 8=PCMA, matching enforceG711()'s pair.
		out += "<P57>0</P57>\r\n";
		out += "<P58>8</P58>\r\n";
		out += "</config>\r\n";
		out += "</gs_provision>\r\n";
		return out;
	}

	// ── Polycom (Issue #177) ────────────────────────────────────────────────────
	//
	// Polycom is a two-file scheme: every phone fetches a fixed master config
	// named exactly `000000000000.cfg` on boot, which points it at a second,
	// per-phone file (conventionally `<mac>-phone.cfg`) for the actual account.
	// polycomBaseConfigFor() below renders the first; polycomPhoneConfigFor()
	// the second. Neither is wired to a route -- see the file-level comment.
	//
	// Per-phone attribute names (reg.1.address, reg.1.label, reg.1.displayName,
	// reg.1.auth.userId, reg.1.auth.password, reg.1.server.1.address) match
	// multiple independent third-party Polycom UC Software provisioning
	// examples; reg.1.server.1.port, reg.1.server.1.transport and the
	// voice.codecPref.* codec-priority keys are standard, widely-documented UC
	// Software parameter names but were not independently re-confirmed for this
	// change (see the PR description) -- best-effort, not hardware-verified,
	// same status as every renderer in this file.
	inline std::string polycomPhoneConfigFor(const std::string& extension,
		const std::string& serverIp, int serverPort, bool authRequired)
	{
		if (containsCrOrLf(extension))
		{
			return {};
		}

		std::string ext = xmlEscape(extension);
		std::string out;
		out.reserve(1024);
		out += "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\r\n";
		out += "<!-- Auto-generated by pocket-dial. Issues #35, #177. -->\r\n";
		if (authRequired)
		{
			out += "<!-- This extension requires a SIP password pocket-dial cannot provision automatically -->\r\n";
			out += "<!-- (only a one-way hash of it is stored server-side); set reg.1.auth.password by hand. -->\r\n";
		}
		out += "<phone1>\r\n";
		out += "  <reg reg.1.address=\"" + ext + "\"\r\n";
		out += "       reg.1.label=\"" + ext + "\"\r\n";
		out += "       reg.1.displayName=\"" + ext + "\"\r\n";
		out += "       reg.1.auth.userId=\"" + ext + "\"\r\n";
		out += "       reg.1.auth.password=\"\"\r\n";                              // blank -- see rationale above
		out += "       reg.1.server.1.address=\"" + serverIp + "\"\r\n";
		out += "       reg.1.server.1.port=\"" + std::to_string(serverPort) + "\"\r\n";
		out += "       reg.1.server.1.transport=\"UDP\"\r\n";
		out += "       voice.codecPref.G711_Mu=\"1\"\r\n";                         // PCMU, priority 1
		out += "       voice.codecPref.G711_A=\"2\" />\r\n";                       // PCMA, priority 2
		out += "</phone1>\r\n";
		return out;
	}

	// The Polycom master/generic config. Static: carries no per-phone data, so
	// it has no injection surface and needs neither the CRLF guard nor
	// xmlEscape(). APP_FILE_PATH is deliberately omitted rather than left
	// empty: pocket-dial does not host Polycom firmware images, and whether an
	// unprovisioned phone tolerates an <APPLICATION> element with no firmware
	// path at all -- versus erroring on one that names an empty path -- is an
	// open, hardware-verification question this session cannot answer.
	inline std::string polycomBaseConfigFor()
	{
		std::string out;
		out.reserve(512);
		out += "<?xml version=\"1.0\" standalone=\"yes\"?>\r\n";
		out += "<!-- Auto-generated by pocket-dial. Issues #35, #177: master/generic config. -->\r\n";
		out += "<APPLICATION CONFIG_FILES=\"$MACADDRESS-phone.cfg\" "
		       "MISC_FILES=\"\" LOG_FILE_DIRECTORY=\"\" "
		       "OVERRIDES_DIRECTORY=\"\" CONTACTS_DIRECTORY=\"\"/>\r\n";
		return out;
	}

	// ── Cisco SPA / Linksys / Sipura (Issue #177) ──────────────────────────────
	//
	// Format: a <flat-profile> element wrapping one <Tag_N_>value</Tag_N_>
	// element per line-N parameter -- confirmed against Cisco's own SPA100/200
	// series provisioning guide, whose running text and worked examples
	// consistently show the trailing-underscore line-numbered form
	// (Line_Enable_1_, Proxy_1_, User_ID_1_, Auth_ID_1_, Password_1_) and the
	// G711u/G711a codec value strings used below. Use_Auth_ID_1_ is the
	// standard field name from the same product family's admin-UI-derived
	// naming convention but was not independently re-confirmed in that
	// specific guide -- best-effort, not hardware-verified, same status as
	// every renderer in this file.
	//
	// Proxy_1_ folds in a non-default port as "ip:port" (serverAddressFor()):
	// there is no separate proxy-port tag in this format -- the guide's own
	// worked example for this field is "192.168.2.100:6060". An earlier draft
	// invented a Proxy_Port_1_ tag that appears nowhere in the source guide
	// (unknown tags are silently ignored by SPA firmware, so it was dead, not
	// harmful, but wrong to claim as guide-confirmed).
	inline std::string ciscoSpaConfigFor(const std::string& extension,
		const std::string& serverIp, int serverPort, bool authRequired)
	{
		if (containsCrOrLf(extension))
		{
			return {};
		}

		std::string ext = xmlEscape(extension);
		std::string out;
		out.reserve(1024);
		out += "<flat-profile>\r\n";
		out += "<!-- Auto-generated by pocket-dial. Issues #35, #177. -->\r\n";
		if (authRequired)
		{
			out += "<!-- This extension requires a SIP password pocket-dial cannot provision automatically -->\r\n";
			out += "<!-- (only a one-way hash of it is stored server-side); set Password_1_ by hand.        -->\r\n";
		}
		out += "<Line_Enable_1_>Yes</Line_Enable_1_>\r\n";
		out += "<Display_Name_1_>" + ext + "</Display_Name_1_>\r\n";
		out += "<User_ID_1_>" + ext + "</User_ID_1_>\r\n";
		out += "<Auth_ID_1_>" + ext + "</Auth_ID_1_>\r\n";
		out += "<Password_1_></Password_1_>\r\n";                                  // blank -- see rationale above
		out += "<Use_Auth_ID_1_>Yes</Use_Auth_ID_1_>\r\n";
		out += "<Proxy_1_>" + serverAddressFor(serverIp, serverPort) + "</Proxy_1_>\r\n";
		out += "<Register_1_>Yes</Register_1_>\r\n";
		// G711u (PCMU) then G711a (PCMA) -- the two enforceG711() keeps.
		out += "<Preferred_Codec_1_>G711u</Preferred_Codec_1_>\r\n";
		out += "<Second_Preferred_Codec_1_>G711a</Second_Preferred_Codec_1_>\r\n";
		out += "</flat-profile>\r\n";
		return out;
	}

	// ── Vendor detection + dispatch (Issue #177) ───────────────────────────────

	enum class Vendor
	{
		Yealink,
		Grandstream,
		Polycom,
		CiscoSpa,
	};

	// Detects vendor from the provisioning request's User-Agent header.
	// Case-insensitive substring match; falls back to Yealink -- the vendor
	// this file has served since Issue #35 -- when nothing recognized matches,
	// including an empty/missing header.
	//
	// Not wired into the live /config/<mac>.cfg route: HttpServer::HttpRequest
	// does not currently capture User-Agent at all (see parseRequest() and the
	// HttpRequest struct, HttpServer.cpp/.hpp), and extending it is out of this
	// change's scope. See docs/PROVISIONING.md.
	inline Vendor detectVendorFromUserAgent(const std::string& userAgent)
	{
		std::string ua = userAgent;
		std::transform(ua.begin(), ua.end(), ua.begin(),
			[](unsigned char c) { return static_cast<char>(std::tolower(c)); });

		if (ua.find("grandstream") != std::string::npos) return Vendor::Grandstream;
		if (ua.find("polycom") != std::string::npos) return Vendor::Polycom;
		// Cisco acquired Sipura (the original SPA/PAP2 line); Linksys also
		// shipped the same hardware/firmware family under its own brand. All
		// three report a User-Agent containing "SPA" (e.g.
		// "Cisco/SPA504G-7.6.2b", "Linksys/SPA942-5.1.8",
		// "Sipura/SPA-2000-3.1.15"). Require "spa" too so an unrelated Cisco
		// endpoint -- "cisco" alone is a common substring well beyond this one
		// product family -- isn't misdetected into this vendor's config shape.
		bool ciscoFamily = ua.find("cisco") != std::string::npos ||
			ua.find("linksys") != std::string::npos ||
			ua.find("sipura") != std::string::npos;
		if (ciscoFamily && ua.find("spa") != std::string::npos) return Vendor::CiscoSpa;
		return Vendor::Yealink;
	}

	// Renders the per-device config for whichever vendor userAgent maps to.
	// Polycom is a two-file scheme (see polycomBaseConfigFor()); this always
	// returns the per-phone file -- the one actually keyed by MAC, and so the
	// one a single-route dispatcher can serve.
	inline std::string renderProvisioningConfigForUserAgent(const std::string& userAgent,
		const std::string& extension, const std::string& serverIp, int serverPort,
		bool authRequired)
	{
		switch (detectVendorFromUserAgent(userAgent))
		{
			case Vendor::Grandstream:
				return grandstreamConfigFor(extension, serverIp, serverPort, authRequired);
			case Vendor::Polycom:
				return polycomPhoneConfigFor(extension, serverIp, serverPort, authRequired);
			case Vendor::CiscoSpa:
				return ciscoSpaConfigFor(extension, serverIp, serverPort, authRequired);
			case Vendor::Yealink:
			default:
				return yealinkConfigFor(extension, serverIp, serverPort, authRequired);
		}
	}
}

#endif
