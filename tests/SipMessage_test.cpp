#include <gtest/gtest.h>
#include "SipMessage.hpp"
#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

TEST(SipMessage, BasicParse) {
    sockaddr_in s; s.sin_addr.s_addr = inet_addr("127.0.0.1");
    std::string raw = "REGISTER sip:server SIP/2.0\r\n"
                      "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=1\r\n"
                      "From: <sip:100@server>\r\n"
                      "To: <sip:100@server>\r\n"
                      "Call-ID: id\r\n"
                      "CSeq: 1 REGISTER\r\n"
                      "Content-Length: 0\r\n\r\n";
    SipMessage m(raw, s);
    ASSERT_TRUE(m.isValidMessage());
    ASSERT_EQ(std::string(m.getType()), "REGISTER");
}

// ── Issue #265: isValidMessage()'s adversarial coverage ─────────────────────
//
// SECURITY_AUDIT.md's SEC-02 entry always claimed this checks that Via/To/
// From/Call-ID/CSeq are present. Until this change the code checked only a
// non-empty start line and type token -- true of the doc's claim in name
// only. Zero test in this suite fed the parser anything that should be
// REJECTED; every call anywhere asserted isValidMessage() returns true.
// These pin the actual, now-true claim: the message this handler drops must
// be recognizably invalid, not just "a message some other test didn't build".

namespace
{
	sockaddr_in localhost()
	{
		sockaddr_in s{}; s.sin_addr.s_addr = inet_addr("127.0.0.1");
		return s;
	}

	// A message with all five RFC 3261 s8.1.1/s8.2.6.2-mandatory headers
	// present, so each "missing X" test below removes exactly one line from a
	// baseline that is otherwise known-valid.
	std::string validBaseline()
	{
		return
			"INVITE sip:100@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP 127.0.0.1:5060;branch=1\r\n"
			"From: <sip:100@server>\r\n"
			"To: <sip:200@server>\r\n"
			"Call-ID: baseline-id\r\n"
			"CSeq: 1 INVITE\r\n"
			"Content-Length: 0\r\n\r\n";
	}

	// Every line of `raw` whose header NAME matches `headerName` (case-
	// sensitive, matching this wire format's own convention) is dropped.
	std::string withoutHeader(std::string raw, const std::string& headerName)
	{
		const std::string needle = headerName + ":";
		std::string out;
		size_t pos = 0;
		while (pos < raw.size())
		{
			size_t eol = raw.find("\r\n", pos);
			const bool lastLine = (eol == std::string::npos);
			const std::string line = raw.substr(pos, lastLine ? std::string::npos : eol - pos);
			if (line.compare(0, needle.size(), needle) != 0)
			{
				out += line;
				if (!lastLine) out += "\r\n";
			}
			if (lastLine) break;
			pos = eol + 2;
		}
		return out;
	}
}

TEST(SipMessage, EmptyMessageIsInvalid)
{
	SipMessage m(std::string(), localhost());
	EXPECT_FALSE(m.isValidMessage());
}

TEST(SipMessage, TruncatedBinaryGarbageIsInvalid)
{
	// No CRLF anywhere, not ASCII, nothing resembling a start line -- the
	// shape a truncated or corrupted UDP datagram takes on the wire.
	std::string raw(64, '\0');
	for (size_t i = 0; i < raw.size(); ++i) raw[i] = static_cast<char>(i & 0xFF);
	SipMessage m(raw, localhost());
	EXPECT_FALSE(m.isValidMessage());
}

TEST(SipMessage, NoHeaderBodySeparatorIsInvalid)
{
	// A start line with no "\r\n\r\n" (or even a bare "\r\n") after it at
	// all -- splitMessage() has nothing to split, so every header lookup,
	// including getType(), comes back empty.
	SipMessage m("INVITE sip:100@server SIP/2.0", localhost());
	EXPECT_FALSE(m.isValidMessage());
}

TEST(SipMessage, AColonlessHeaderLineLeavesThatHeaderAbsent)
{
	// The pre-#265 check would have accepted this: the start line and type
	// token both parse fine, and neither depended on any individual header.
	// "ViaSIP/2.0/UDP ..." matches no header name (getVia() requires the
	// literal "Via:" prefix to identify the line), so it is exactly as absent
	// as if the line were never sent at all.
	std::string raw = withoutHeader(validBaseline(), "Via");
	raw.insert(raw.find("From:"), "ViaSIP/2.0/UDP 127.0.0.1:5060;branch=1\r\n");
	SipMessage m(raw, localhost());
	EXPECT_FALSE(m.isValidMessage())
		<< "a malformed Via line must count as Via being absent, not present-but-odd";
}

TEST(SipMessage, MissingViaIsInvalid)
{
	SipMessage m(withoutHeader(validBaseline(), "Via"), localhost());
	EXPECT_FALSE(m.isValidMessage());
}

TEST(SipMessage, MissingToIsInvalid)
{
	SipMessage m(withoutHeader(validBaseline(), "To"), localhost());
	EXPECT_FALSE(m.isValidMessage());
}

TEST(SipMessage, MissingFromIsInvalid)
{
	SipMessage m(withoutHeader(validBaseline(), "From"), localhost());
	EXPECT_FALSE(m.isValidMessage());
}

TEST(SipMessage, MissingCallIdIsInvalid)
{
	SipMessage m(withoutHeader(validBaseline(), "Call-ID"), localhost());
	EXPECT_FALSE(m.isValidMessage());
}

TEST(SipMessage, MissingCSeqIsInvalid)
{
	SipMessage m(withoutHeader(validBaseline(), "CSeq"), localhost());
	EXPECT_FALSE(m.isValidMessage());
}

TEST(SipMessage, AllFiveHeadersPresentIsStillValid)
{
	// The other half of "present" -- a message missing NONE of the five must
	// not have become collateral damage from #265's stricter check.
	SipMessage m(validBaseline(), localhost());
	EXPECT_TRUE(m.isValidMessage());
}

// Self-audit follow-up (#265 was clean here, but this was untested): the four
// of the five headers that HAVE an RFC 3261 s7.3.3 compact form -- v/f/t/i for
// Via/From/To/Call-ID -- must still count as present when a phone sends the
// compact form instead of the long one. getVia()/getFrom()/getTo()/
// getCallID() already pass both names to findHeaderIndex() (pre-existing,
// unchanged by #265); this pins that #265's new checks inherit that, rather
// than assuming it from reading the accessor once. CSeq has no compact form
// in RFC 3261, so it is deliberately not part of this test.
TEST(SipMessage, CompactFormHeadersStillCountAsPresent)
{
	std::string raw =
		"INVITE sip:100@server SIP/2.0\r\n"
		"v: SIP/2.0/UDP 127.0.0.1:5060;branch=1\r\n"
		"f: <sip:100@server>\r\n"
		"t: <sip:200@server>\r\n"
		"i: compact-id\r\n"
		"CSeq: 1 INVITE\r\n"
		"Content-Length: 0\r\n\r\n";
	SipMessage m(raw, localhost());
	EXPECT_TRUE(m.isValidMessage())
		<< "compact-form Via/From/To/Call-ID must satisfy #265's presence check, "
		   "same as the long form";
}

// Regression: enforceG711() rewrites the SDP m= codec list, which changes the
// body size. It must resync Content-Length, otherwise the 777 echo / 999 page
// answer is dropped by the peer as truncated and the caller sits on ringback.
TEST(SipMessage, EnforceG711ResyncsContentLength) {
    sockaddr_in s; s.sin_addr.s_addr = inet_addr("127.0.0.1");
    std::string body =
        "v=0\r\n"
        "o=- 0 0 IN IP4 127.0.0.1\r\n"
        "s=-\r\n"
        "c=IN IP4 127.0.0.1\r\n"
        "t=0 0\r\n"
        "m=audio 5004 RTP/AVP 0 8 9 18 101\r\n"
        "a=rtpmap:0 PCMU/8000\r\n";
    std::string head =
        "INVITE sip:777@server SIP/2.0\r\n"
        "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=1\r\n"
        "From: <sip:100@server>\r\n"
        "To: <sip:777@server>\r\n"
        "Call-ID: id\r\n"
        "CSeq: 1 INVITE\r\n"
        "Content-Type: application/sdp\r\n"
        "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n";
    SipMessage m(head + body, s);

    m.enforceG711();

    // Codec list collapsed to PCMU/PCMA + telephone-event.
    ASSERT_NE(m.toString().find("m=audio 5004 RTP/AVP 0 8 101\r\n"), std::string::npos);

    // Content-Length must equal the actual body byte count after the rewrite.
    const std::string out = m.toString();
    size_t sep = out.find("\r\n\r\n");
    ASSERT_NE(sep, std::string::npos);
    size_t actualBody = out.size() - (sep + 4);
    ASSERT_EQ(std::string(m.getContentLength()),
              "Content-Length: " + std::to_string(actualBody));
}

// Guard test for the SipMessage storage rewrite (owned header-line list replacing
// the shared _messageStr + string_view fields). SipMessage only ever names ~8
// headers (Via/From/To/Call-ID/CSeq/Contact/Content-Length/Authorization); every
// other header on the wire — including headers repeated more than once, like the
// triple Alert-Info the intercom auto-answer path emits (RequestsHandler.cpp) —
// must ride along untouched. A naive "N owned fields, drop the shared buffer"
// rewrite would silently lose all of these on the first mutation. This test must
// stay green across the rewrite.
TEST(SipMessage, PreservesUnknownAndRepeatedHeadersOnMutation) {
    sockaddr_in s; s.sin_addr.s_addr = inet_addr("127.0.0.1");
    std::string raw =
        "INVITE sip:999@server SIP/2.0\r\n"
        "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=1\r\n"
        "From: <sip:100@server>\r\n"
        "To: <sip:999@server>\r\n"
        "Call-ID: guard-id\r\n"
        "CSeq: 1 INVITE\r\n"
        "Contact: <sip:100@127.0.0.1:5060>\r\n"
        "Call-Info: <sip:any>;answer-after=0\r\n"
        "Alert-Info: info=alert-autoanswer\r\n"
        "Alert-Info: answer-after=0\r\n"
        "Alert-Info: intercom=true\r\n"
        "P-Auto-Answer: normal\r\n"
        "WWW-Authenticate: Digest realm=\"pocketdial\", nonce=\"abc123\"\r\n"
        "Content-Type: application/sdp\r\n"
        "Content-Length: 0\r\n\r\n";

    SipMessage unmodified(raw, s);
    ASSERT_EQ(unmodified.toString(), raw) << "byte-identical round trip with no mutation";

    SipMessage m(raw, s);
    m.setVia("Via: SIP/2.0/UDP 127.0.0.1:5060;branch=1;received=10.0.0.1");
    const std::string out = m.toString();

    ASSERT_NE(out.find("Call-Info: <sip:any>;answer-after=0"), std::string::npos);
    ASSERT_NE(out.find("P-Auto-Answer: normal"), std::string::npos);
    ASSERT_NE(out.find("WWW-Authenticate: Digest realm=\"pocketdial\", nonce=\"abc123\""), std::string::npos);
    ASSERT_NE(out.find("Content-Type: application/sdp"), std::string::npos);

    size_t alertInfoCount = 0;
    for (size_t pos = out.find("Alert-Info:"); pos != std::string::npos;
         pos = out.find("Alert-Info:", pos + 1))
    {
        ++alertInfoCount;
    }
    ASSERT_EQ(alertInfoCount, 3u) << "all three repeated Alert-Info headers must survive a mutation";
    ASSERT_NE(out.find("Alert-Info: info=alert-autoanswer"), std::string::npos);
    ASSERT_NE(out.find("Alert-Info: answer-after=0"), std::string::npos);
    ASSERT_NE(out.find("Alert-Info: intercom=true"), std::string::npos);

    // Fields untouched by the mutation must still read correctly too.
    ASSERT_EQ(std::string(m.getCallID()), "Call-ID: guard-id");
    ASSERT_EQ(std::string(m.getContact()), "Contact: <sip:100@127.0.0.1:5060>");
}
