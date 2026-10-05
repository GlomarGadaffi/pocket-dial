// RegisteredContact_test.cpp: issues #797 and #798.
//
// A phone registers a Contact URI, and that URI is where the PBX must address
// requests it sends to the phone (RFC 3261 §10.2.1, §12.2.1.1). A Snom 370
// registers `<sip:1001@ip:1037;line=h2k6k1ih>` and refuses (404 on OPTIONS,
// 481 on BYE) any request whose Request-URI lacks the ;line= parameter.
//
//   #797  the OPTIONS keepalive rebuilt the Request-URI as sip:<ext>@<ip>:<port>.
//   #798  the callee's BYE was relayed to the caller with the Request-URI the
//         callee had addressed to the PBX, and the caller's 481 was not treated
//         as the session being over (RFC 3261 §15.1.2), so the slot leaked.
//   #754  every other request relayed to a phone kept the Request-URI its sender
//         had addressed to the PBX.

#include <gtest/gtest.h>

#include <chrono>
#include <string>
#include <vector>

#include "IDGen.hpp"
#include "PoolConfig.hpp"
#include "RequestsHandler.hpp"
#include "SipHeaderUtil.hpp"

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#else
#include <arpa/inet.h>
#endif

namespace
{
	using Sent = std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>>;

	const char* const kPbxIp = "192.168.31.1";
	const char* const kSnomIp = "192.168.31.10";
	const char* const kYealinkIp = "192.168.31.20";
	const char* const kSnomContactUri = "sip:100@192.168.31.10:1037;line=h2k6k1ih";

	sockaddr_in addrFor(const std::string& ip, uint16_t port)
	{
		sockaddr_in a{};
		a.sin_family = AF_INET;
		a.sin_addr.s_addr = inet_addr(ip.c_str());
		a.sin_port = htons(port);
		return a;
	}

	std::shared_ptr<SipMessage> makeRegister(const std::string& ext, const std::string& ip, uint16_t port,
	                                         const std::string& contactLine)
	{
		std::string raw =
			"REGISTER sip:server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + ip + ":" + std::to_string(port) + ";branch=z9hG4bKreg" + ext + "\r\n"
			"From: <sip:" + ext + "@server>;tag=rt" + ext + "\r\n"
			"To: <sip:" + ext + "@server>\r\n"
			"Call-ID: reg-" + ext + "\r\n"
			"CSeq: 1 REGISTER\r\n" +
			contactLine +
			"Expires: 3600\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addrFor(ip, port));
	}

	std::string snomContactLine()
	{
		return std::string("Contact: <") + kSnomContactUri + ">;reg-id=1\r\n";
	}

	std::string sdpBody()
	{
		return "v=0\r\no=- 0 0 IN IP4 10.0.0.1\r\ns=-\r\nc=IN IP4 10.0.0.1\r\nt=0 0\r\n"
		       "m=audio 10000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\n";
	}

	std::string headerLine(const std::string& raw, const std::string& name)
	{
		size_t pos = 0;
		while (pos < raw.size())
		{
			size_t eol = raw.find("\r\n", pos);
			if (eol == std::string::npos) eol = raw.size();
			std::string line = raw.substr(pos, eol - pos);
			if (line.size() > name.size() && line.compare(0, name.size(), name) == 0) return line;
			pos = eol + 2;
		}
		return {};
	}

	std::string requestLineOf(const std::string& raw)
	{
		return raw.substr(0, raw.find("\r\n"));
	}

	// The most recent message sent to `addr` whose text contains `needle`.
	std::string findSentTo(const Sent& sent, const sockaddr_in& addr, const std::string& needle)
	{
		for (auto it = sent.rbegin(); it != sent.rend(); ++it)
		{
			if (it->first.sin_addr.s_addr != addr.sin_addr.s_addr) continue;
			if (it->first.sin_port != addr.sin_port) continue;
			if (!it->second) continue;
			std::string raw = it->second->toString();
			if (raw.find(needle) != std::string::npos) return raw;
		}
		return {};
	}

	// Snom (100) calls Yealink (106), Yealink answers. Returns the Call-ID.
	std::string connectCall(RequestsHandler& handler, Sent& sent, const std::string& callId,
	                        const std::string& yealinkContactLine = "Contact: <sip:106@192.168.31.20:5062>\r\n")
	{
		handler.handle(makeRegister("100", kSnomIp, 1037, snomContactLine()));
		handler.handle(makeRegister("106", kYealinkIp, 5062, yealinkContactLine));

		std::string body = sdpBody();
		std::string invite =
			"INVITE sip:106@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + std::string(kSnomIp) + ":1037;branch=z9hG4bKinv" + callId + "\r\n"
			"From: <sip:100@server>;tag=ft" + callId + "\r\n"
			"To: <sip:106@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Max-Forwards: 70\r\n"
			"Contact: <" + std::string(kSnomContactUri) + ">\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		handler.handle(RequestsHandler::getMessageFromPool(invite, addrFor(kSnomIp, 1037)));

		std::string fork = findSentTo(sent, addrFor(kYealinkIp, 5062), "INVITE sip:106@");
		EXPECT_FALSE(fork.empty()) << "the call must be forwarded to 106";
		std::string ok =
			"SIP/2.0 200 OK\r\n" +
			headerLine(fork, "Via:") + "\r\n" +
			headerLine(fork, "From:") + "\r\n"
			"To: <sip:106@server>;tag=ans106\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Contact: <sip:106@192.168.31.20:5062>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		handler.handle(RequestsHandler::getMessageFromPool(ok, addrFor(kYealinkIp, 5062)));
		EXPECT_EQ(handler.getSession("Call-ID: " + callId).value()->getState(), Session::State::Connected);
		return callId;
	}

	// The callee hangs up, addressing its BYE to the PBX exactly as a phone does
	// with the Contact the PBX presented (#754).
	std::shared_ptr<SipMessage> calleeBye(const std::string& callId)
	{
		std::string raw =
			"BYE sip:100@" + std::string(kPbxIp) + ":5060;transport=UDP SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + std::string(kYealinkIp) + ":5062;branch=z9hG4bKbye" + callId + "\r\n"
			"From: <sip:106@server>;tag=ans106\r\n"
			"To: <sip:100@server>;tag=ft" + callId + "\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 7 BYE\r\n"
			"Max-Forwards: 70\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addrFor(kYealinkIp, 5062));
	}

	// The caller hangs up, from its own Via and with its own dialog tags.
	std::shared_ptr<SipMessage> callerBye(const std::string& callId)
	{
		std::string raw =
			"BYE sip:106@" + std::string(kPbxIp) + ":5060;transport=UDP SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + std::string(kSnomIp) + ":1037;branch=z9hG4bKcbye" + callId + "\r\n"
			"From: <sip:100@server>;tag=ft" + callId + "\r\n"
			"To: <sip:106@server>;tag=ans106\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 9 BYE\r\n"
			"Max-Forwards: 70\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addrFor(kSnomIp, 1037));
	}

	// A response to the request `rawRequest`, built the way a phone does: its Via,
	// From, To, Call-ID and CSeq copied back (RFC 3261 §8.2.6.2).
	std::shared_ptr<SipMessage> answerTo(const std::string& rawRequest, const std::string& status,
	                                     const sockaddr_in& from)
	{
		std::string raw =
			"SIP/2.0 " + status + "\r\n" +
			headerLine(rawRequest, "Via:") + "\r\n" +
			headerLine(rawRequest, "From:") + "\r\n" +
			headerLine(rawRequest, "To:") + "\r\n" +
			headerLine(rawRequest, "Call-ID:") + "\r\n" +
			headerLine(rawRequest, "CSeq:") + "\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, from);
	}

	// How many messages to `addr` contain `needle`.
	int countSentTo(const Sent& sent, const sockaddr_in& addr, const std::string& needle)
	{
		int n = 0;
		for (const auto& [to, msg] : sent)
		{
			if (to.sin_addr.s_addr != addr.sin_addr.s_addr || to.sin_port != addr.sin_port || !msg) continue;
			if (msg->toString().find(needle) != std::string::npos) ++n;
		}
		return n;
	}

	// The PBX's own top Via on the BYE it originated: its address and a fresh branch,
	// neither of the phones'.
	void expectPbxViaOnBye(const std::string& bye, const std::string& phoneIp)
	{
		EXPECT_EQ(headerLine(bye, "Via:").rfind(std::string("Via: SIP/2.0/UDP ") + kPbxIp + ":5060;branch=z9hG4bK", 0), 0u)
			<< "#808: the PBX's own Via on the BYE it sends, so the far phone answers port 5060: " << headerLine(bye, "Via:");
		EXPECT_EQ(bye.find(phoneIp), std::string::npos)
			<< "#808: the sender's Via must not survive into the PBX's BYE";
		EXPECT_EQ(bye.find("z9hG4bKbye"), std::string::npos) << "the sender's branch must not be reused";
		EXPECT_EQ(bye.find("z9hG4bKcbye"), std::string::npos) << "the sender's branch must not be reused";
	}

	// Every free message-pool slot but `spare`, held by the caller.
	std::vector<std::shared_ptr<SipMessage>> holdAllButSpare(size_t spare)
	{
		std::vector<std::shared_ptr<SipMessage>> held;
		for (size_t i = 0;; ++i)
		{
			auto m = makeRegister("199", "192.168.31.99", 5060, "");
			if (!m) break;
			held.push_back(std::move(m));
		}
		for (size_t i = 0; i < spare && !held.empty(); ++i) held.pop_back();
		return held;
	}
}

TEST(RegisteredContact, OptionsPingRequestUriCarriesTheRegisteredContactUri)
{
	Sent sent;
	RequestsHandler handler(kPbxIp, 5060,
		[&sent](const sockaddr_in& a, std::shared_ptr<SipMessage> m) { sent.emplace_back(a, std::move(m)); });
	handler.handle(makeRegister("100", kSnomIp, 1037, snomContactLine()));

	handler.tick();

	const std::string ping = findSentTo(sent, addrFor(kSnomIp, 1037), "OPTIONS ");
	ASSERT_FALSE(ping.empty()) << "a freshly registered phone must be pinged on the first tick";
	EXPECT_EQ(requestLineOf(ping), std::string("OPTIONS ") + kSnomContactUri + " SIP/2.0")
		<< "#797: the Request-URI must be the registered Contact URI, ;line= included";
}

TEST(RegisteredContact, OptionsPingFallsBackToTheObservedAddressWhenNoContactWasRegistered)
{
	Sent sent;
	RequestsHandler handler(kPbxIp, 5060,
		[&sent](const sockaddr_in& a, std::shared_ptr<SipMessage> m) { sent.emplace_back(a, std::move(m)); });
	handler.handle(makeRegister("100", kSnomIp, 1037, ""));

	handler.tick();

	const std::string ping = findSentTo(sent, addrFor(kSnomIp, 1037), "OPTIONS ");
	ASSERT_FALSE(ping.empty());
	EXPECT_EQ(requestLineOf(ping), "OPTIONS sip:100@192.168.31.10:1037 SIP/2.0")
		<< "no stored Contact: the pre-#797 form is kept";
}

TEST(RegisteredContact, AQuotedDisplayNameDoesNotHideTheRegisteredContactUri)
{
	// #824 (same class): contactUriView() took the first '<' on the line, even
	// one inside the quoted display name (RFC 3261 s25.1), so the stored Contact
	// was the display name's text, or nothing, and the ping lost its ;line=.
	for (const char* name : {"\"Lobby <1>\" ", "\"Desk <sip:100@192.168.31.10:1037>\" ",
	                         "\"Desk \\\" <x>\" ",   // an escaped quote keeps the name open
	                         "\"Lobby 55\" TV\" ",   // #832 review: a quote left open, last <...> wins
	                         "\"Snom 370\" "})        // control: no '<' in the name
	{
		SCOPED_TRACE(name);
		Sent sent;
		RequestsHandler handler(kPbxIp, 5060,
			[&sent](const sockaddr_in& a, std::shared_ptr<SipMessage> m) { sent.emplace_back(a, std::move(m)); });
		handler.handle(makeRegister("100", kSnomIp, 1037,
			std::string("Contact: ") + name + "<" + kSnomContactUri + ">;reg-id=1\r\n"));

		handler.tick();

		const std::string ping = findSentTo(sent, addrFor(kSnomIp, 1037), "OPTIONS ");
		ASSERT_FALSE(ping.empty());
		EXPECT_EQ(requestLineOf(ping), std::string("OPTIONS ") + kSnomContactUri + " SIP/2.0");
	}
}

TEST(RegisteredContact, AQuotedSipInstanceDoesNotHideTheRegisteredContactUri)
{
	// #835: with a quote left open in the display name, the quote that opens
	// +sip.instance's value (RFC 5626) closed it, so "<urn:uuid:...>" sat
	// outside quotes and was read as the URI. The stored Contact was lost and
	// the ping went out without ;line=, which a Snom answers 404.
	const std::string instance = ";reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-1000-8000-000413a1b2c3>\"";
	for (const std::string& contact : {
			"\"Lobby 55\" TV\" <" + std::string(kSnomContactUri) + ">" + instance,
			// Controls: a balanced display name, and an open quote in the
			// parameter itself, after the URI.
			"\"Snom 370\" <" + std::string(kSnomContactUri) + ">" + instance,
			"<" + std::string(kSnomContactUri) + ">;reg-id=1;+sip.instance=\"<urn:uuid:0>"})
	{
		SCOPED_TRACE(contact);
		Sent sent;
		RequestsHandler handler(kPbxIp, 5060,
			[&sent](const sockaddr_in& a, std::shared_ptr<SipMessage> m) { sent.emplace_back(a, std::move(m)); });
		auto reg = makeRegister("100", kSnomIp, 1037, "Contact: " + contact + "\r\n");
		EXPECT_EQ(reg->getContactNumber(), "100");
		handler.handle(reg);

		handler.tick();

		const std::string ping = findSentTo(sent, addrFor(kSnomIp, 1037), "OPTIONS ");
		ASSERT_FALSE(ping.empty());
		EXPECT_EQ(requestLineOf(ping), std::string("OPTIONS ") + kSnomContactUri + " SIP/2.0");
	}
	// An open quote with no <...> at all names no URI, as before.
	EXPECT_TRUE(siphdr::contactUriView("Contact: \"Lobby sip:100@192.168.31.10:1037").empty());
}

TEST(RegisteredContact, AnUppercaseSchemeContactIsKept)
{
	// #835 nit: RFC 3261 s19.1.4, the scheme is case-insensitive. The stored
	// Contact took only "sip:" and "sips:", so this one was dropped and the
	// ping lost its ;line=. It is used as the phone registered it.
	for (const char* uri : {"SIP:100@192.168.31.10:1037;line=h2k6k1ih", "Sip:100@192.168.31.10:1037;line=h2k6k1ih"})
	{
		SCOPED_TRACE(uri);
		Sent sent;
		RequestsHandler handler(kPbxIp, 5060,
			[&sent](const sockaddr_in& a, std::shared_ptr<SipMessage> m) { sent.emplace_back(a, std::move(m)); });
		handler.handle(makeRegister("100", kSnomIp, 1037, std::string("Contact: <") + uri + ">;reg-id=1\r\n"));

		handler.tick();

		const std::string ping = findSentTo(sent, addrFor(kSnomIp, 1037), "OPTIONS ");
		ASSERT_FALSE(ping.empty());
		EXPECT_EQ(requestLineOf(ping), std::string("OPTIONS ") + uri + " SIP/2.0");
	}
}

TEST(RegisteredContact, TheUriScanPicksABracketOrNothingOnEveryShortLine)
{
	// #857 review S2: every line of up to 8 of '"', '\', '<', '>', ';', 'a'.
	// The URI's '<' is npos or a '<'. With balanced quotes it is the first '<'
	// outside them; with one left open, a first '<' that no quote precedes
	// (S1). The stored Contact is a view inside the line.
	constexpr size_t npos = std::string_view::npos;
	const char alphabet[] = {'"', '\\', '<', '>', ';', 'a'};
	char buf[8] = {};
	size_t lines = 0;
	size_t bad = 0;
	std::string firstBad;
	for (size_t len = 0; len <= sizeof(buf); ++len)
	{
		size_t total = 1;
		for (size_t i = 0; i < len; ++i) total *= sizeof(alphabet);
		for (size_t n = 0; n < total; ++n, ++lines)
		{
			size_t k = n;
			for (size_t i = 0; i < len; ++i, k /= sizeof(alphabet)) buf[i] = alphabet[k % sizeof(alphabet)];
			const std::string_view v(buf, len);

			bool quoted = false;
			size_t first = npos;
			for (size_t i = 0; i < len; ++i)
			{
				if (quoted) { if (v[i] == '\\') ++i; else if (v[i] == '"') quoted = false; }
				else if (v[i] == '"') quoted = true;
				else if (v[i] == '<' && first == npos) first = i;
			}
			bool open = false;
			const size_t lt = siphdr::nameAddrOpen(v, open);
			const std::string_view c = siphdr::contactUriView(v);
			const bool ok = (lt == npos || v[lt] == '<') && open == quoted && (open || lt == first) &&
				!(open && first != npos && v.substr(0, first).find('"') == npos && lt != first) &&
				(c.empty() || (c.data() >= v.data() && c.data() + c.size() <= v.data() + v.size()));
			if (!ok && bad++ == 0) firstBad = std::string(v);
		}
	}
	EXPECT_EQ(lines, 2015539u);
	EXPECT_EQ(bad, 0u) << "first: " << firstBad;
}

TEST(RegisteredContact, RelayedByeIsAddressedToTheCallersRegisteredContact)
{
	Sent sent;
	RequestsHandler handler(kPbxIp, 5060,
		[&sent](const sockaddr_in& a, std::shared_ptr<SipMessage> m) { sent.emplace_back(a, std::move(m)); });
	const std::string callId = connectCall(handler, sent, "rc-bye-relay");

	handler.handle(calleeBye(callId));

	// #808: the BYE the caller gets is the PBX's own, so it carries the PBX's CSeq,
	// not the callee's "7".
	const std::string atCaller = findSentTo(sent, addrFor(kSnomIp, 1037), "BYE ");
	ASSERT_FALSE(atCaller.empty()) << "the callee's hang-up must reach the caller";
	EXPECT_EQ(requestLineOf(atCaller), std::string("BYE ") + kSnomContactUri + " SIP/2.0")
		<< "#798: the Request-URI is the caller's Contact, not the PBX's own address";
}

TEST(RegisteredContact, A481ToTheRelayedByeFreesTheSession)
{
	Sent sent;
	RequestsHandler handler(kPbxIp, 5060,
		[&sent](const sockaddr_in& a, std::shared_ptr<SipMessage> m) { sent.emplace_back(a, std::move(m)); });
	const std::string callId = connectCall(handler, sent, "rc-bye-481");
	handler.handle(calleeBye(callId));
	ASSERT_TRUE(handler.getSession("Call-ID: " + callId).has_value()) << "precondition: the session waits for the caller's answer";

	// #808: the 481 answers the BYE the PBX sent (its Via, its branch), not the callee's.
	const std::string byeAtCaller = findSentTo(sent, addrFor(kSnomIp, 1037), "BYE ");
	ASSERT_FALSE(byeAtCaller.empty());
	const int toCalleeBefore = static_cast<int>(sent.size());
	handler.handle(answerTo(byeAtCaller, "481 Call/Transaction Does Not Exist", addrFor(kSnomIp, 1037)));

	EXPECT_FALSE(handler.getSession("Call-ID: " + callId).has_value())
		<< "#798: RFC 3261 §15.1.2: a 481 to a BYE means the session is over, the slot must be freed";
	EXPECT_EQ(static_cast<int>(sent.size()), toCalleeBefore)
		<< "#808: the callee was already answered 200; the 481 is not relayed to it";
}

TEST(RegisteredContact, ServerOriginatedByeIsAddressedToTheRegisteredContact)
{
	Sent sent;
	RequestsHandler handler(kPbxIp, 5060,
		[&sent](const sockaddr_in& a, std::shared_ptr<SipMessage> m) { sent.emplace_back(a, std::move(m)); });
	const std::string callId = connectCall(handler, sent, "rc-bye-server");

	handler.forceDisconnect("106");
	handler.tick();   // drainOutbox() merges _asyncOutbox

	const std::string atCaller = findSentTo(sent, addrFor(kSnomIp, 1037), "BYE ");
	ASSERT_FALSE(atCaller.empty()) << "the admin kill must BYE the caller";
	EXPECT_EQ(requestLineOf(atCaller), std::string("BYE ") + kSnomContactUri + " SIP/2.0")
		<< "a BYE the PBX authors itself needs the registered Contact too";
}

// ── #744 B2a: the server BYE's bytes are main's ──────────────────────────────────
//
// buildServerBye() moved from an ostringstream onto sipb::bye(). With IDGen's bytes
// pinned, an admin kill puts on the wire byte for byte what main 20a4722 sent, for
// both Request-URI forms #798 picks between: the Contact the Snom registered, and
// the observed address of a phone that registered none.
namespace
{
	uint8_t g_nextIdByte = 0;

	// Counts up, so every identifier differs and an ID drawn twice, or drawn in a
	// different order, shows in the bytes. The destructor puts the real source back
	// even when an ASSERT ends the test early.
	struct CountingIds
	{
		CountingIds()
		{
			g_nextIdByte = 0;
			IDGen::setByteSourceForTest([](uint8_t* buf, size_t len) {
				for (size_t i = 0; i < len; ++i) buf[i] = g_nextIdByte++;
			});
		}
		~CountingIds() { IDGen::setByteSourceForTest(nullptr); }
		CountingIds(const CountingIds&) = delete;
		CountingIds& operator=(const CountingIds&) = delete;
	};
}

TEST(RegisteredContact, ServerByeBytesAreMainsForBothRequestUriForms)
{
	Sent sent;
	RequestsHandler handler(kPbxIp, 5060,
		[&sent](const sockaddr_in& a, std::shared_ptr<SipMessage> m) { sent.emplace_back(a, std::move(m)); });
	connectCall(handler, sent, "rc-bye-bytes", "");   // 106 registers no Contact
	{
		CountingIds ids;
		ASSERT_TRUE(handler.forceDisconnect("106"));
	}
	handler.tick();   // drainOutbox() merges _asyncOutbox

	// The same two strings are SipMessageBuilder.ByeIsMainsBytesFor*'s goldens.
	EXPECT_EQ(findSentTo(sent, addrFor(kSnomIp, 1037), "BYE "),
		"BYE sip:100@192.168.31.10:1037;line=h2k6k1ih SIP/2.0\r\n"
		"Via: SIP/2.0/UDP 192.168.31.1:5060;branch=z9hG4bK0123456789AB\r\n"
		"From: <sip:106@server>;tag=ans106\r\n"
		"To: <sip:100@server>;tag=ftrc-bye-bytes\r\n"
		"Call-ID: rc-bye-bytes\r\n"
		"CSeq: 2 BYE\r\n"
		"Max-Forwards: 70\r\n"
		"Content-Length: 0\r\n"
		"\r\n");
	EXPECT_EQ(findSentTo(sent, addrFor(kYealinkIp, 5062), "BYE "),
		"BYE sip:106@192.168.31.20:5062 SIP/2.0\r\n"
		"Via: SIP/2.0/UDP 192.168.31.1:5060;branch=z9hG4bKGHIJKLMNOPQR\r\n"
		"From: <sip:100@server>;tag=ftrc-bye-bytes\r\n"
		"To: <sip:106@server>;tag=ans106\r\n"
		"Call-ID: rc-bye-bytes\r\n"
		"CSeq: 2 BYE\r\n"
		"Max-Forwards: 70\r\n"
		"Content-Length: 0\r\n"
		"\r\n");
}

// ── #808: an ordinary relayed call's BYE is answered locally ─────────────────────
//
// Relaying the sender's BYE untouched kept only the sender's Via, so the far phone
// answered it to the sender's port on the PBX's IP (RFC 3261 §18.2.2), the PBX never
// saw the 200, the sender retransmitted to Timer F and the session never freed. The
// PBX now answers the sender 200 itself and sends its own BYE.

TEST(ByeLocalAnswer, CalleeByeIsAnsweredAndTheCallerGetsThePbxsOwnBye)
{
	Sent sent;
	RequestsHandler handler(kPbxIp, 5060,
		[&sent](const sockaddr_in& a, std::shared_ptr<SipMessage> m) { sent.emplace_back(a, std::move(m)); });
	const std::string callId = connectCall(handler, sent, "bye808-callee");
	const sockaddr_in yealink = addrFor(kYealinkIp, 5062);
	const sockaddr_in snom = addrFor(kSnomIp, 1037);

	handler.handle(calleeBye(callId));

	const std::string ok = findSentTo(sent, yealink, "SIP/2.0 200");
	ASSERT_FALSE(ok.empty()) << "#808: the sender's transaction is completed by the PBX";
	EXPECT_NE(ok.find("CSeq: 7 BYE"), std::string::npos);
	EXPECT_NE(ok.find("branch=z9hG4bKbye" + callId), std::string::npos) << "its own Via branch, echoed";

	const std::string bye = findSentTo(sent, snom, "BYE ");
	ASSERT_FALSE(bye.empty()) << "the caller must be told";
	EXPECT_EQ(requestLineOf(bye), std::string("BYE ") + kSnomContactUri + " SIP/2.0");
	expectPbxViaOnBye(bye, kYealinkIp);
	EXPECT_EQ(countSentTo(sent, snom, "BYE "), 1);
	ASSERT_TRUE(handler.getSession("Call-ID: " + callId).has_value())
		<< "the session waits for the caller's answer";

	const size_t before = sent.size();
	handler.handle(answerTo(bye, "200 OK", snom));
	EXPECT_FALSE(handler.getSession("Call-ID: " + callId).has_value())
		<< "the caller's 200 to the PBX's BYE frees the session";
	EXPECT_EQ(sent.size(), before) << "and is not relayed to the callee, who already has its 200";
}

TEST(ByeLocalAnswer, CallerByeIsAnsweredAndTheCalleeGetsThePbxsOwnBye)
{
	Sent sent;
	RequestsHandler handler(kPbxIp, 5060,
		[&sent](const sockaddr_in& a, std::shared_ptr<SipMessage> m) { sent.emplace_back(a, std::move(m)); });
	const std::string callId = connectCall(handler, sent, "bye808-caller");
	const sockaddr_in yealink = addrFor(kYealinkIp, 5062);
	const sockaddr_in snom = addrFor(kSnomIp, 1037);

	handler.handle(callerBye(callId));

	const std::string ok = findSentTo(sent, snom, "SIP/2.0 200");
	ASSERT_FALSE(ok.empty()) << "#808: the sender's transaction is completed by the PBX";
	EXPECT_NE(ok.find("CSeq: 9 BYE"), std::string::npos);

	const std::string bye = findSentTo(sent, yealink, "BYE ");
	ASSERT_FALSE(bye.empty()) << "the callee must be told";
	EXPECT_EQ(requestLineOf(bye), "BYE sip:106@192.168.31.20:5062 SIP/2.0");
	expectPbxViaOnBye(bye, kSnomIp);
	EXPECT_EQ(countSentTo(sent, yealink, "BYE "), 1);

	const size_t before = sent.size();
	handler.handle(answerTo(bye, "200 OK", yealink));
	EXPECT_FALSE(handler.getSession("Call-ID: " + callId).has_value())
		<< "the callee's 200 to the PBX's BYE frees the session";
	EXPECT_EQ(sent.size(), before) << "and is not relayed to the caller";
}

TEST(ByeLocalAnswer, ARetransmittedByeIsAnsweredAgainAndOriginatesNoSecondBye)
{
	Sent sent;
	RequestsHandler handler(kPbxIp, 5060,
		[&sent](const sockaddr_in& a, std::shared_ptr<SipMessage> m) { sent.emplace_back(a, std::move(m)); });
	const std::string callId = connectCall(handler, sent, "bye808-retx");
	const sockaddr_in yealink = addrFor(kYealinkIp, 5062);
	const sockaddr_in snom = addrFor(kSnomIp, 1037);

	handler.handle(calleeBye(callId));
	handler.handle(calleeBye(callId));   // same branch: the callee never saw the first 200

	EXPECT_EQ(countSentTo(sent, yealink, "CSeq: 7 BYE"), 2) << "answered again, RFC 3261 §17.2.2";
	EXPECT_EQ(countSentTo(sent, snom, "BYE "), 1) << "no second BYE toward the caller";
}

TEST(ByeLocalAnswer, AByeCrossingTheOneInFlightIsAnsweredAndOriginatesNothing)
{
	Sent sent;
	RequestsHandler handler(kPbxIp, 5060,
		[&sent](const sockaddr_in& a, std::shared_ptr<SipMessage> m) { sent.emplace_back(a, std::move(m)); });
	const std::string callId = connectCall(handler, sent, "bye808-cross");
	const sockaddr_in yealink = addrFor(kYealinkIp, 5062);
	const sockaddr_in snom = addrFor(kSnomIp, 1037);

	handler.handle(calleeBye(callId));
	handler.handle(callerBye(callId));   // the caller hung up at the same moment

	EXPECT_EQ(countSentTo(sent, snom, "CSeq: 9 BYE"), 1) << "the caller's own BYE is answered";
	EXPECT_EQ(countSentTo(sent, yealink, "BYE "), 0) << "and does not make the PBX BYE the phone that hung up";
	EXPECT_EQ(countSentTo(sent, snom, "BYE "), 1);
}

TEST(ByeLocalAnswer, AByeTheFarPhoneNeverAnswersStillEndsTheSessionAtTimerF)
{
	Sent sent;
	RequestsHandler handler(kPbxIp, 5060,
		[&sent](const sockaddr_in& a, std::shared_ptr<SipMessage> m) { sent.emplace_back(a, std::move(m)); });
	const std::string callId = connectCall(handler, sent, "bye808-timerf");

	handler.handle(calleeBye(callId));
	ASSERT_TRUE(handler.getSession("Call-ID: " + callId).has_value()) << "precondition: waiting for the caller";

	handler.sweepTransactionsForTest(std::chrono::steady_clock::now() + std::chrono::seconds(10));
	EXPECT_TRUE(handler.getSession("Call-ID: " + callId).has_value()) << "not before Timer F";

	handler.sweepTransactionsForTest(std::chrono::steady_clock::now() + std::chrono::seconds(33));
	EXPECT_FALSE(handler.getSession("Call-ID: " + callId).has_value())
		<< "#808: Timer F on the PBX's BYE (RFC 3261 §17.1.2.2) ends the session it was waiting on";
}

TEST(ByeLocalAnswer, ARefusedPoolDrawCommitsNothingAndTheRetransmitSucceeds)
{
	Sent sent;
	RequestsHandler handler(kPbxIp, 5060,
		[&sent](const sockaddr_in& a, std::shared_ptr<SipMessage> m) { sent.emplace_back(a, std::move(m)); });
	const std::string callId = connectCall(handler, sent, "bye808-pool");
	const sockaddr_in yealink = addrFor(kYealinkIp, 5062);
	const sockaddr_in snom = addrFor(kSnomIp, 1037);
	const size_t before = sent.size();

	{
		auto held = holdAllButSpare(1);   // the BYE datagram itself takes the last slot
		auto bye = calleeBye(callId);
		ASSERT_NE(bye, nullptr);
		handler.handle(bye);
		EXPECT_EQ(sent.size(), before) << "#715: no 200 and no BYE when they cannot both be drawn";
		EXPECT_EQ(handler.getSession("Call-ID: " + callId).value()->getState(), Session::State::Connected)
			<< "and no state committed, so the retransmit starts clean";
	}

	handler.handle(calleeBye(callId));
	EXPECT_EQ(countSentTo(sent, yealink, "CSeq: 7 BYE"), 1);
	EXPECT_EQ(countSentTo(sent, snom, "BYE "), 1);
}

// #744 B2a: unlike a refused pool draw (#715, above), a BYE sipb::bye() refuses is
// refused again on every retransmit, so it must not keep the sender unanswered.
// Here the sender's own From, which the far leg's BYE carries, is too long for
// sipb::kMaxByeBytes.
TEST(ByeLocalAnswer, AByeTheBuilderRefusesStillAnswersTheSenderAndEndsTheSession)
{
	Sent sent;
	RequestsHandler handler(kPbxIp, 5060,
		[&sent](const sockaddr_in& a, std::shared_ptr<SipMessage> m) { sent.emplace_back(a, std::move(m)); });
	const std::string callId = connectCall(handler, sent, "bye744-long");
	const sockaddr_in yealink = addrFor(kYealinkIp, 5062);
	const sockaddr_in snom = addrFor(kSnomIp, 1037);

	const std::string raw =
		"BYE sip:100@" + std::string(kPbxIp) + ":5060;transport=UDP SIP/2.0\r\n"
		"Via: SIP/2.0/UDP " + std::string(kYealinkIp) + ":5062;branch=z9hG4bKbye" + callId + "\r\n"
		"From: \"" + std::string(700, 'x') + "\" <sip:106@server>;tag=ans106\r\n"
		"To: <sip:100@server>;tag=ft" + callId + "\r\n"
		"Call-ID: " + callId + "\r\n"
		"CSeq: 7 BYE\r\n"
		"Max-Forwards: 70\r\n"
		"Content-Length: 0\r\n\r\n";
	handler.handle(RequestsHandler::getMessageFromPool(raw, yealink));

	const std::string ok = findSentTo(sent, yealink, "CSeq: 7 BYE");
	EXPECT_EQ(ok.rfind("SIP/2.0 200", 0), 0u) << "the sender's BYE is answered 200: " << requestLineOf(ok);
	EXPECT_EQ(countSentTo(sent, snom, "BYE "), 0) << "nothing partial goes to the far leg";
	EXPECT_EQ(handler.getByeTruncated(), 1u) << "and the refusal is counted for /api/status";
	EXPECT_FALSE(handler.getSession("Call-ID: " + callId).has_value())
		<< "no BYE is out whose answer would end the session, so it ends here";
}

// ── #754: a request relayed to a phone is addressed to the Contact it registered ──
//
// A phone addresses the PBX (the Contact the PBX presented, #425), so the
// Request-URI it writes names the PBX. Every request the PBX passes on to a phone
// must name that phone the way #797/#798 do: the URI it registered, URI parameters
// intact, and sip:<ext>@<ip>:<port> only when it registered none. The Snom
// registers a Contact with a ;line= parameter, the Yealink one without; each test
// runs with the Snom on the receiving end and again with the Yealink.
namespace
{
	struct Phone
	{
		std::string ext;
		std::string ip;
		uint16_t port;
		std::string contactUri;   // the URI it registers
	};

	Phone snomPhone() { return {"100", kSnomIp, 1037, kSnomContactUri}; }
	Phone yealinkPhone() { return {"106", kYealinkIp, 5062, "sip:106@192.168.31.20:5062"}; }

	sockaddr_in addrOf(const Phone& p) { return addrFor(p.ip, p.port); }

	void registerPhone(RequestsHandler& handler, const Phone& p)
	{
		handler.handle(makeRegister(p.ext, p.ip, p.port, "Contact: <" + p.contactUri + ">;reg-id=1\r\n"));
	}

	std::string viaOf(const Phone& p, const std::string& branch)
	{
		return "Via: SIP/2.0/UDP " + p.ip + ":" + std::to_string(p.port) + ";branch=" + branch + "\r\n";
	}

	// `from` dials `dialed`, addressing the PBX as a phone does.
	std::shared_ptr<SipMessage> dial(const Phone& from, const std::string& dialed, const std::string& callId)
	{
		const std::string body = sdpBody();
		const std::string raw =
			"INVITE sip:" + dialed + "@" + kPbxIp + ":5060 SIP/2.0\r\n" +
			viaOf(from, "z9hG4bKdial" + callId) +
			"From: <sip:" + from.ext + "@server>;tag=ft" + callId + "\r\n"
			"To: <sip:" + dialed + "@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Max-Forwards: 70\r\n"
			"Contact: <" + from.contactUri + ">\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		return RequestsHandler::getMessageFromPool(raw, addrOf(from));
	}

	// The CANCEL of dial(from, to.ext, callId): its branch, Request-URI, From and To (RFC 3261 §9.1).
	std::shared_ptr<SipMessage> cancelDial(const Phone& from, const Phone& to, const std::string& callId)
	{
		const std::string raw =
			"CANCEL sip:" + to.ext + "@" + kPbxIp + ":5060 SIP/2.0\r\n" +
			viaOf(from, "z9hG4bKdial" + callId) +
			"From: <sip:" + from.ext + "@server>;tag=ft" + callId + "\r\n"
			"To: <sip:" + to.ext + "@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 CANCEL\r\n"
			"Max-Forwards: 70\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addrOf(from));
	}

	// A request in the call's dialog from `from` to `to`, addressed to the PBX's
	// Contact for `to` (#425).
	std::shared_ptr<SipMessage> inDialog(const std::string& method, const Phone& from, const std::string& fromTag,
	                                     const Phone& to, const std::string& toTag, const std::string& callId,
	                                     int cseq, bool withSdp)
	{
		const std::string body = withSdp ? sdpBody() : std::string();
		const std::string raw =
			method + " sip:" + to.ext + "@" + kPbxIp + ":5060;transport=UDP SIP/2.0\r\n" +
			viaOf(from, "z9hG4bK" + method + std::to_string(cseq) + callId) +
			"From: <sip:" + from.ext + "@server>;tag=" + fromTag + "\r\n"
			"To: <sip:" + to.ext + "@server>;tag=" + toTag + "\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: " + std::to_string(cseq) + " " + method + "\r\n"
			"Max-Forwards: 70\r\n" +
			(method == "ACK" || method == "BYE" ? std::string() : "Contact: <" + from.contactUri + ">\r\n") +
			(withSdp ? "Content-Type: application/sdp\r\n" : "") +
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		return RequestsHandler::getMessageFromPool(raw, addrOf(from));
	}

	// `phone`'s answer to the request `relayed` it received (RFC 3261 §8.2.6.2), with
	// its own To tag when the request had none.
	std::shared_ptr<SipMessage> answer(const std::string& relayed, const std::string& status, const Phone& phone,
	                                   const std::string& toTag, bool withSdp)
	{
		std::string to = headerLine(relayed, "To:");
		if (to.find(";tag=") == std::string::npos) to += ";tag=" + toTag;
		const std::string body = withSdp ? sdpBody() : std::string();
		const std::string raw =
			"SIP/2.0 " + status + "\r\n" +
			headerLine(relayed, "Via:") + "\r\n" +
			headerLine(relayed, "From:") + "\r\n" +
			to + "\r\n" +
			headerLine(relayed, "Call-ID:") + "\r\n" +
			headerLine(relayed, "CSeq:") + "\r\n"
			"Contact: <" + phone.contactUri + ">\r\n" +
			(withSdp ? "Content-Type: application/sdp\r\n" : "") +
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		return RequestsHandler::getMessageFromPool(raw, addrOf(phone));
	}

	std::string requestUriOf(const std::string& raw)
	{
		const std::string line = requestLineOf(raw);
		const size_t sp1 = line.find(' ');
		const size_t sp2 = line.find(' ', sp1 + 1);
		return sp1 == std::string::npos || sp2 == std::string::npos ? std::string() : line.substr(sp1 + 1, sp2 - sp1 - 1);
	}

	struct Pairing
	{
		Phone caller;
		Phone callee;
	};

	// The Snom answering the Yealink, then the Yealink answering the Snom.
	std::vector<Pairing> bothWays() { return {{yealinkPhone(), snomPhone()}, {snomPhone(), yealinkPhone()}}; }
}

// The caller's INVITE, the ACK for the 2xx, a re-INVITE with its ACK, and an UPDATE
// reach the callee at the URI it registered. The responses relayed back to the
// caller keep their status lines.
TEST(RelayedRequestUri, EveryRequestTowardTheCalleeCarriesItsRegisteredContact)
{
	for (const auto& [caller, callee] : bothWays())
	{
		SCOPED_TRACE("callee registered " + callee.contactUri);
		Sent sent;
		RequestsHandler handler(kPbxIp, 5060,
			[&sent](const sockaddr_in& a, std::shared_ptr<SipMessage> m) { sent.emplace_back(a, std::move(m)); });
		registerPhone(handler, caller);
		registerPhone(handler, callee);
		const std::string callId = "ruri-to-callee-" + callee.ext;
		const std::string callerTag = "ft" + callId;
		const std::string calleeTag = "ans" + callee.ext;

		handler.handle(dial(caller, callee.ext, callId));
		const std::string invite = findSentTo(sent, addrOf(callee), "CSeq: 1 INVITE");
		ASSERT_FALSE(invite.empty()) << "the call must reach the callee";
		EXPECT_EQ(requestLineOf(invite), "INVITE " + callee.contactUri + " SIP/2.0");

		handler.handle(answer(invite, "180 Ringing", callee, calleeTag, false));
		EXPECT_EQ(requestLineOf(findSentTo(sent, addrOf(caller), "CSeq: 1 INVITE")), "SIP/2.0 180 Ringing")
			<< "a relayed response keeps its status line";
		handler.handle(answer(invite, "200 OK", callee, calleeTag, true));
		EXPECT_EQ(requestLineOf(findSentTo(sent, addrOf(caller), "CSeq: 1 INVITE")), "SIP/2.0 200 OK")
			<< "a relayed response keeps its status line";

		handler.handle(inDialog("ACK", caller, callerTag, callee, calleeTag, callId, 1, false));
		EXPECT_EQ(requestLineOf(findSentTo(sent, addrOf(callee), "CSeq: 1 ACK")),
			"ACK " + callee.contactUri + " SIP/2.0");

		handler.handle(inDialog("INVITE", caller, callerTag, callee, calleeTag, callId, 2, true));
		const std::string reinvite = findSentTo(sent, addrOf(callee), "CSeq: 2 INVITE");
		ASSERT_FALSE(reinvite.empty()) << "the re-INVITE must reach the callee";
		EXPECT_EQ(requestLineOf(reinvite), "INVITE " + callee.contactUri + " SIP/2.0");
		handler.handle(answer(reinvite, "200 OK", callee, calleeTag, true));
		EXPECT_EQ(requestLineOf(findSentTo(sent, addrOf(caller), "CSeq: 2 INVITE")), "SIP/2.0 200 OK");
		handler.handle(inDialog("ACK", caller, callerTag, callee, calleeTag, callId, 2, false));
		EXPECT_EQ(requestLineOf(findSentTo(sent, addrOf(callee), "CSeq: 2 ACK")),
			"ACK " + callee.contactUri + " SIP/2.0");

		handler.handle(inDialog("UPDATE", caller, callerTag, callee, calleeTag, callId, 3, false));
		EXPECT_EQ(requestLineOf(findSentTo(sent, addrOf(callee), "CSeq: 3 UPDATE")),
			"UPDATE " + callee.contactUri + " SIP/2.0");
	}
}

// The other direction: the callee's re-INVITE, its ACK and an UPDATE reach the
// caller at the URI the caller registered.
TEST(RelayedRequestUri, EveryRequestTowardTheCallerCarriesItsRegisteredContact)
{
	for (const auto& [caller, callee] : bothWays())
	{
		SCOPED_TRACE("caller registered " + caller.contactUri);
		Sent sent;
		RequestsHandler handler(kPbxIp, 5060,
			[&sent](const sockaddr_in& a, std::shared_ptr<SipMessage> m) { sent.emplace_back(a, std::move(m)); });
		registerPhone(handler, caller);
		registerPhone(handler, callee);
		const std::string callId = "ruri-to-caller-" + caller.ext;
		const std::string callerTag = "ft" + callId;
		const std::string calleeTag = "ans" + callee.ext;

		handler.handle(dial(caller, callee.ext, callId));
		const std::string invite = findSentTo(sent, addrOf(callee), "CSeq: 1 INVITE");
		ASSERT_FALSE(invite.empty()) << "the call must reach the callee";
		handler.handle(answer(invite, "200 OK", callee, calleeTag, true));
		handler.handle(inDialog("ACK", caller, callerTag, callee, calleeTag, callId, 1, false));

		handler.handle(inDialog("INVITE", callee, calleeTag, caller, callerTag, callId, 11, true));
		const std::string reinvite = findSentTo(sent, addrOf(caller), "CSeq: 11 INVITE");
		ASSERT_FALSE(reinvite.empty()) << "the callee's re-INVITE must reach the caller";
		EXPECT_EQ(requestLineOf(reinvite), "INVITE " + caller.contactUri + " SIP/2.0");
		handler.handle(answer(reinvite, "200 OK", caller, callerTag, true));
		EXPECT_EQ(requestLineOf(findSentTo(sent, addrOf(callee), "CSeq: 11 INVITE")), "SIP/2.0 200 OK")
			<< "a relayed response keeps its status line";
		handler.handle(inDialog("ACK", callee, calleeTag, caller, callerTag, callId, 11, false));
		EXPECT_EQ(requestLineOf(findSentTo(sent, addrOf(caller), "CSeq: 11 ACK")),
			"ACK " + caller.contactUri + " SIP/2.0");

		handler.handle(inDialog("UPDATE", callee, calleeTag, caller, callerTag, callId, 12, false));
		EXPECT_EQ(requestLineOf(findSentTo(sent, addrOf(caller), "CSeq: 12 UPDATE")),
			"UPDATE " + caller.contactUri + " SIP/2.0");
	}
}

// RFC 3261 §9.1: a CANCEL carries the Request-URI of the INVITE it cancels, so the
// relayed CANCEL names the callee exactly as the relayed INVITE did.
TEST(RelayedRequestUri, ACancelReachesTheRingingCalleeAtTheUriItsInviteCarried)
{
	for (const auto& [caller, callee] : bothWays())
	{
		SCOPED_TRACE("callee registered " + callee.contactUri);
		Sent sent;
		RequestsHandler handler(kPbxIp, 5060,
			[&sent](const sockaddr_in& a, std::shared_ptr<SipMessage> m) { sent.emplace_back(a, std::move(m)); });
		registerPhone(handler, caller);
		registerPhone(handler, callee);
		const std::string callId = "ruri-cancel-" + callee.ext;

		handler.handle(dial(caller, callee.ext, callId));
		const std::string invite = findSentTo(sent, addrOf(callee), "CSeq: 1 INVITE");
		ASSERT_FALSE(invite.empty()) << "the call must reach the callee";
		handler.handle(answer(invite, "180 Ringing", callee, "ans" + callee.ext, false));

		handler.handle(cancelDial(caller, callee, callId));
		const std::string cancel = findSentTo(sent, addrOf(callee), "CSeq: 1 CANCEL");
		ASSERT_FALSE(cancel.empty()) << "the CANCEL must reach the callee";
		EXPECT_EQ(requestLineOf(cancel), "CANCEL " + callee.contactUri + " SIP/2.0");
		EXPECT_EQ(requestUriOf(cancel), requestUriOf(invite)) << "RFC 3261 §9.1";
	}
}

// RFC 3261 §15: a caller may BYE an early dialog. With no answer yet the session has
// no far leg, so onBye() relays the caller's own BYE after naming the callee's
// registered Contact on it (#798). The relay must not rewrite that again.
TEST(RelayedRequestUri, AnEarlyDialogByeKeepsTheCalleesRegisteredContact)
{
	for (const auto& [caller, callee] : bothWays())
	{
		SCOPED_TRACE("callee registered " + callee.contactUri);
		Sent sent;
		RequestsHandler handler(kPbxIp, 5060,
			[&sent](const sockaddr_in& a, std::shared_ptr<SipMessage> m) { sent.emplace_back(a, std::move(m)); });
		registerPhone(handler, caller);
		registerPhone(handler, callee);
		const std::string callId = "ruri-early-bye-" + callee.ext;
		const std::string calleeTag = "ans" + callee.ext;

		handler.handle(dial(caller, callee.ext, callId));
		const std::string invite = findSentTo(sent, addrOf(callee), "CSeq: 1 INVITE");
		ASSERT_FALSE(invite.empty()) << "the call must reach the callee";
		handler.handle(answer(invite, "180 Ringing", callee, calleeTag, false));

		handler.handle(inDialog("BYE", caller, "ft" + callId, callee, calleeTag, callId, 2, false));
		const std::string bye = findSentTo(sent, addrOf(callee), "CSeq: 2 BYE");
		ASSERT_FALSE(bye.empty()) << "the early-dialog BYE must reach the callee";
		EXPECT_EQ(requestLineOf(bye), "BYE " + callee.contactUri + " SIP/2.0");
	}
}

// A pickup CANCELs the ringing target with a copy of the INVITE the session kept,
// and ACKs the target's 487 the same way (#749, #750). Both must carry the
// Request-URI the target's INVITE carried (RFC 3261 §9.1, §17.1.1.3).
TEST(RelayedRequestUri, APickupCancelAndThe487AckCarryTheUriOfTheInviteTheTargetGot)
{
	for (const auto& [caller, target] : bothWays())
	{
		SCOPED_TRACE("target registered " + target.contactUri);
		Sent sent;
		RequestsHandler handler(kPbxIp, 5060,
			[&sent](const sockaddr_in& a, std::shared_ptr<SipMessage> m) { sent.emplace_back(a, std::move(m)); });
		const Phone picker{"102", "192.168.31.30", 5060, "sip:102@192.168.31.30:5060"};
		registerPhone(handler, caller);
		registerPhone(handler, target);
		registerPhone(handler, picker);
		handler.setRingGroup("600", target.ext + "," + picker.ext, "ringall");
		const std::string callId = "ruri-pickup-" + target.ext;

		handler.handle(dial(caller, target.ext, callId));
		const std::string invite = findSentTo(sent, addrOf(target), "CSeq: 1 INVITE");
		ASSERT_FALSE(invite.empty()) << "the call must reach the target";
		EXPECT_EQ(requestUriOf(invite), target.contactUri);

		handler.handle(dial(picker, "**" + target.ext, "ruri-picker-" + target.ext));
		const std::string cancel = findSentTo(sent, addrOf(target), "CANCEL ");
		ASSERT_FALSE(cancel.empty()) << "the pickup must CANCEL the ringing target";
		EXPECT_EQ(requestUriOf(cancel), requestUriOf(invite)) << "RFC 3261 §9.1";

		handler.handle(answer(invite, "487 Request Terminated", target, "ans" + target.ext, false));
		const std::string ack = findSentTo(sent, addrOf(target), "CSeq: 1 ACK");
		ASSERT_FALSE(ack.empty()) << "the PBX ACKs the target's 487 (#750)";
		EXPECT_EQ(requestUriOf(ack), requestUriOf(invite)) << "RFC 3261 §17.1.1.3";
	}
}

// A request whose To is no registered phone is not relayed: the sender is answered
// 404 and the request itself is left as it came.
TEST(RelayedRequestUri, ARequestForAnUnregisteredExtensionIsAnsweredNotRetargeted)
{
	Sent sent;
	RequestsHandler handler(kPbxIp, 5060,
		[&sent](const sockaddr_in& a, std::shared_ptr<SipMessage> m) { sent.emplace_back(a, std::move(m)); });
	const Phone snom = snomPhone();
	const Phone nobody{"107", "192.168.31.40", 5060, "sip:107@192.168.31.40:5060"};
	registerPhone(handler, snom);

	auto bye = inDialog("BYE", snom, "ftx", nobody, "tox", "ruri-nobody", 5, false);
	ASSERT_NE(bye, nullptr);
	const std::string before = requestLineOf(bye->toString());
	handler.handle(bye);

	EXPECT_EQ(requestLineOf(bye->toString()), before) << "nothing to retarget it to";
	EXPECT_EQ(requestLineOf(findSentTo(sent, addrOf(snom), "CSeq: 5 BYE")), "SIP/2.0 404 Not Found");
	EXPECT_EQ(countSentTo(sent, addrOf(nobody), "BYE"), 0);
}

// SipClient keeps a registered Contact of up to kMaxContactUriLen bytes; the
// Request-URI carries all of it. A longer one is not stored, and the request still
// goes out, addressed to the phone's observed address.
TEST(RelayedRequestUri, AFullLengthContactIsCarriedWholeAndAnOverlongOneFallsBack)
{
	const std::string prefix = "sip:106@192.168.31.20:5062;line=";
	for (const size_t len : {SipClient::kMaxContactUriLen, SipClient::kMaxContactUriLen + 1})
	{
		SCOPED_TRACE("Contact URI of " + std::to_string(len) + " bytes");
		Sent sent;
		RequestsHandler handler(kPbxIp, 5060,
			[&sent](const sockaddr_in& a, std::shared_ptr<SipMessage> m) { sent.emplace_back(a, std::move(m)); });
		Phone callee = yealinkPhone();
		callee.contactUri = prefix + std::string(len - prefix.size(), 'x');
		const Phone caller = snomPhone();
		registerPhone(handler, caller);
		registerPhone(handler, callee);
		const std::string expected = len <= SipClient::kMaxContactUriLen ? callee.contactUri
		                                                                 : "sip:106@192.168.31.20:5062";
		const std::string callId = "ruri-long-" + std::to_string(len);

		handler.handle(dial(caller, callee.ext, callId));
		const std::string invite = findSentTo(sent, addrOf(callee), "CSeq: 1 INVITE");
		ASSERT_FALSE(invite.empty()) << "the INVITE must still go out";
		EXPECT_EQ(requestLineOf(invite), "INVITE " + expected + " SIP/2.0");

		handler.handle(answer(invite, "200 OK", callee, "ans106", true));
		handler.handle(inDialog("INVITE", caller, "ft" + callId, callee, "ans106", callId, 2, true));
		EXPECT_EQ(requestLineOf(findSentTo(sent, addrOf(callee), "CSeq: 2 INVITE")), "INVITE " + expected + " SIP/2.0");
	}
}
