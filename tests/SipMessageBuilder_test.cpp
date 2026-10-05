// SipMessageBuilder_test.cpp — bounded, zero-heap SIP message builder (RFC 3261).
// Part of Issue #744 (strangler plan: builder track B1).

#include <gtest/gtest.h>

#include <cstring>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "IDGen.hpp"
#include "SipMessageBuilder.hpp"
#include "support/AllocCounter.hpp"

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#else
#include <arpa/inet.h>
#endif

namespace
{

bool startsWith(std::string_view s, std::string_view prefix)
{
	return s.size() >= prefix.size() && s.substr(0, prefix.size()) == prefix;
}

bool endsWith(std::string_view s, std::string_view suffix)
{
	return s.size() >= suffix.size() && s.substr(s.size() - suffix.size()) == suffix;
}

std::string headerValue(std::string_view raw, std::string_view name)
{
	size_t pos = 0;
	while (pos < raw.size())
	{
		size_t eol = raw.find("\r\n", pos);
		if (eol == std::string_view::npos) eol = raw.size();
		if (eol == pos) break;
		if (raw.substr(pos, name.size() + 1) == std::string(name) + ":")
		{
			size_t v = pos + name.size() + 1;
			while (v < eol && raw[v] == ' ') ++v;
			return std::string(raw.substr(v, eol - v));
		}
		pos = eol + 2;
	}
	return {};
}

} // namespace

// B1: options() emits a well-formed RFC 3261 request with magic cookie,
// CSeq 1 OPTIONS, Content-Length 0, and Max-Forwards 70.
TEST(SipMessageBuilder, OptionsEmitsValidRfc3261Request)
{
	sipb::OptionsWire wire{};
	sipb::OptionsParams params{};
	params.targetAor = "101";
	params.destIp = "192.168.1.50";
	params.destPort = 5060;
	params.localIp = "192.168.1.1";
	params.localPort = 5060;
	params.fromUser = "server";

	const sipb::Err err = sipb::options(wire, params);
	ASSERT_EQ(err, sipb::Err::Ok);
	ASSERT_GT(wire.len, 0u);
	ASSERT_LT(wire.len, sizeof(wire.bytes));

	std::string_view raw(wire.bytes, wire.len);

	// Start line
	EXPECT_TRUE(startsWith(raw, "OPTIONS sip:101@192.168.1.50:5060 SIP/2.0\r\n"))
		<< "start line mismatch:\n" << raw;

	// Via header must have RFC 3261 magic cookie branch (z9hG4bK + 12 chars)
	const std::string via = headerValue(raw, "Via");
	EXPECT_TRUE(startsWith(via, "SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK")) << via;
	const size_t b = via.find(";branch=z9hG4bK");
	ASSERT_NE(b, std::string::npos);
	EXPECT_EQ(via.size() - (b + 15), 12u) << "branch must have exactly 12 random chars: " << via;

	// To and From headers
	EXPECT_EQ(headerValue(raw, "To"), "<sip:101@192.168.1.50:5060>");
	const std::string from = headerValue(raw, "From");
	EXPECT_TRUE(startsWith(from, "<sip:server@192.168.1.1:5060>;tag=")) << from;
	const size_t tagPos = from.find(";tag=");
	ASSERT_NE(tagPos, std::string::npos);
	EXPECT_EQ(from.size() - (tagPos + 5), 9u) << "fromTag must have 9 random chars: " << from;

	// Call-ID must be 15 chars + @ + localIp
	const std::string callId = headerValue(raw, "Call-ID");
	const size_t at = callId.find('@');
	ASSERT_NE(at, std::string::npos) << callId;
	EXPECT_EQ(at, 15u) << "Call-ID random prefix must be 15 chars: " << callId;
	EXPECT_EQ(callId.substr(at + 1), "192.168.1.1");

	// Invariant headers
	EXPECT_EQ(headerValue(raw, "CSeq"), "1 OPTIONS");
	EXPECT_EQ(headerValue(raw, "Max-Forwards"), "70");
	EXPECT_EQ(headerValue(raw, "User-Agent"), "pocket-dial");
	EXPECT_EQ(headerValue(raw, "Content-Length"), "0");
	EXPECT_TRUE(endsWith(raw, "\r\n\r\n"));
}

// B1: options() performs ZERO heap allocations post-init.
TEST(SipMessageBuilder, OptionsAllocatesZeroHeap)
{
	// Positive control: the counter moves on a new (same shape as AllocBaseline).
	{
		static void* volatile sink = nullptr;
		AllocGuard positiveControl;
		int* p = new int(1234);
		sink = p;
		const size_t n = positiveControl.delta();
		delete p;
		EXPECT_GT(n, 0u);
	}

	sipb::OptionsWire wire{};
	sipb::OptionsParams params{};
	params.targetAor = "102";
	params.destIp = "192.168.12.244";
	params.destPort = 5060;
	params.localIp = "192.168.12.1";
	params.localPort = 5060;

	AllocGuard guard;
	const sipb::Err err = sipb::options(wire, params);
	const size_t allocs = guard.delta();

	EXPECT_EQ(err, sipb::Err::Ok);
	EXPECT_EQ(allocs, 0u) << "sipb::options must never touch the heap";
}

// B1: An oversized input or bad field fails safely with len = 0 and Err.
TEST(SipMessageBuilder, OptionsTruncationFailsSafely)
{
	sipb::OptionsWire wire{};
	sipb::OptionsParams badParams{};
	// Empty targetAor
	EXPECT_EQ(sipb::options(wire, badParams), sipb::Err::BadField);
	EXPECT_EQ(wire.len, 0u);

	// Oversized target AOR exceeding wire buffer
	std::string hugeAor(sizeof(wire.bytes) + 100, 'x');
	sipb::OptionsParams hugeParams{};
	hugeParams.targetAor = hugeAor;
	hugeParams.destIp = "192.168.1.1";
	hugeParams.localIp = "192.168.1.2";

	EXPECT_EQ(sipb::options(wire, hugeParams), sipb::Err::Truncated);
	EXPECT_EQ(wire.len, 0u) << "truncated build must zero out len (never send partial)";
}

// The 640 B cap itself: the longest message that fits is 639 B; one more byte
// is Truncated with len = 0. The IDs are fixed-length, so the size is a
// function of requestUri alone.
TEST(SipMessageBuilder, OptionsCapBoundaryIs639Bytes)
{
	sipb::OptionsWire wire{};
	sipb::OptionsParams params{};
	params.targetAor = "100";
	params.destIp = "192.168.31.10";
	params.destPort = 1037;
	params.localIp = "192.168.1.1";
	params.localPort = 5060;

	std::string uri = "sip:a";
	params.requestUri = uri;
	ASSERT_EQ(sipb::options(wire, params), sipb::Err::Ok);
	const size_t base = wire.len;
	ASSERT_LT(base, sizeof(wire.bytes) - 1);

	uri.append(sizeof(wire.bytes) - 1 - base, 'x');
	params.requestUri = uri;
	ASSERT_EQ(sipb::options(wire, params), sipb::Err::Ok);
	EXPECT_EQ(wire.len, sizeof(wire.bytes) - 1) << "639 B must fit";

	uri.push_back('x');
	params.requestUri = uri;
	EXPECT_EQ(sipb::options(wire, params), sipb::Err::Truncated);
	EXPECT_EQ(wire.len, 0u) << "640 B must not fit, and len must be 0";
}

// Defense in depth behind SipClient::setContactUri: a request line can't carry
// a byte that would split or end the message.
TEST(SipMessageBuilder, OptionsRefusesControlBytesInTheRequestUri)
{
	sipb::OptionsWire wire{};
	sipb::OptionsParams params{};
	params.targetAor = "100";
	params.destIp = "192.168.31.10";
	params.destPort = 1037;
	params.localIp = "192.168.1.1";
	params.localPort = 5060;

	for (const std::string bad : {std::string("sip:a\r\nVia: x"), std::string("sip:a b"),
	                              std::string("sip:a\0b", 7), std::string("sip:a\x7f")})
	{
		params.requestUri = bad;
		EXPECT_EQ(sipb::options(wire, params), sipb::Err::BadField);
		EXPECT_EQ(wire.len, 0u);
	}
}

// B1: the random identifiers come from IDGen's CSPRNG path and nothing else
// (#385). A local PRNG would ignore the injected byte source and fail this.
TEST(SipMessageBuilder, OptionsIdsComeFromIdGen)
{
	sipb::OptionsParams params{};
	params.targetAor = "101";
	params.destIp = "192.168.1.50";
	params.destPort = 5060;
	params.localIp = "192.168.1.1";
	params.localPort = 5060;
	IDGen::setByteSourceForTest([](uint8_t* buf, size_t len) {
		for (size_t i = 0; i < len; ++i) buf[i] = 1;   // 0x01 -> alphabet[1] == '1'
	});
	sipb::OptionsWire wire{};
	const sipb::Err err = sipb::options(wire, params);
	IDGen::setByteSourceForTest(nullptr);

	ASSERT_EQ(err, sipb::Err::Ok);
	const std::string_view raw(wire.bytes, wire.len);
	EXPECT_EQ(headerValue(raw, "Call-ID"), "111111111111111@192.168.1.1");
	EXPECT_NE(raw.find(";branch=z9hG4bK111111111111\r\n"), std::string_view::npos) << raw;
	EXPECT_NE(raw.find(";tag=111111111\r\n"), std::string_view::npos) << raw;
}

// #797: the Request-URI is the Contact the phone registered, parameters and
// all; To stays the composed AOR.
TEST(SipMessageBuilder, OptionsRequestUriIsTheRegisteredContactVerbatim)
{
	sipb::OptionsWire wire{};
	sipb::OptionsParams params{};
	params.targetAor = "100";
	params.destIp = "192.168.31.10";
	params.destPort = 1037;
	params.localIp = "192.168.1.1";
	params.localPort = 5060;
	params.requestUri = "sip:100@192.168.31.10:1037;line=h2k6k1ih";

	ASSERT_EQ(sipb::options(wire, params), sipb::Err::Ok);
	const std::string_view raw(wire.bytes, wire.len);
	EXPECT_TRUE(startsWith(raw, "OPTIONS sip:100@192.168.31.10:1037;line=h2k6k1ih SIP/2.0\r\n")) << raw;
	EXPECT_EQ(headerValue(raw, "To"), "<sip:100@192.168.31.10:1037>");
}

// #797: with no registered Contact the Request-URI is composed from the
// observed address, byte for byte what the pre-builder ping sent.
TEST(SipMessageBuilder, OptionsRequestUriFallsBackToTheObservedAddress)
{
	sipb::OptionsWire wire{};
	sipb::OptionsParams params{};
	params.targetAor = "100";
	params.destIp = "192.168.31.10";
	params.destPort = 1037;
	params.localIp = "192.168.1.1";
	params.localPort = 5060;

	ASSERT_EQ(sipb::options(wire, params), sipb::Err::Ok);
	const std::string_view raw(wire.bytes, wire.len);
	EXPECT_TRUE(startsWith(raw, "OPTIONS sip:100@192.168.31.10:1037 SIP/2.0\r\n")) << raw;
}

// ── B2a: bye(), what RequestsHandler::buildServerBye() sends ─────────────────────

namespace
{

uint8_t g_nextIdByte = 0;

// IDGen's bytes count up from `start`, as in RegisteredContact.ServerByeBytesAre-
// MainsForBothRequestUriForms. The destructor puts the real source back even
// when an ASSERT ends the test early.
struct CountingIds
{
	explicit CountingIds(uint8_t start)
	{
		g_nextIdByte = start;
		IDGen::setByteSourceForTest([](uint8_t* buf, size_t len) {
			for (size_t i = 0; i < len; ++i) buf[i] = g_nextIdByte++;
		});
	}
	~CountingIds() { IDGen::setByteSourceForTest(nullptr); }
	CountingIds(const CountingIds&) = delete;
	CountingIds& operator=(const CountingIds&) = delete;
};

sipb::ByeParams validBye()
{
	sipb::ByeParams p{};
	p.requestUri = "sip:100@192.168.31.10:1037;line=h2k6k1ih";
	p.targetUser = "100";
	p.destIp = "192.168.31.10";
	p.destPort = 1037;
	p.localIp = "192.168.31.1";
	p.localPort = 5060;
	p.from = "<sip:106@server>;tag=ans106";
	p.to = "<sip:100@server>;tag=ft1";
	p.callId = "c1@192.168.31.10";
	p.cseq = 2;
	return p;
}

} // namespace

// Golden bytes. The inputs are the ones forceDisconnect("106") hands
// buildServerBye() for the caller's leg in RegisteredContact.ServerByeBytesAre-
// MainsForBothRequestUriForms (the session's whole header lines, From and To
// swapped for that leg); the expected string is what main 20a4722 sent for them.
TEST(SipMessageBuilder, ByeIsMainsBytesForTheRegisteredContact)
{
	sipb::ByeParams p{};
	p.requestUri = "sip:100@192.168.31.10:1037;line=h2k6k1ih";
	p.targetUser = "100";
	p.destIp = "192.168.31.10";
	p.destPort = 1037;
	p.localIp = "192.168.31.1";
	p.localPort = 5060;
	p.from = "To: <sip:106@server>;tag=ans106";
	p.to = "From: <sip:100@server>;tag=ftrc-bye-bytes";
	p.callId = "Call-ID: rc-bye-bytes";
	p.cseq = 2;

	sipb::ByeWire wire;
	{
		CountingIds ids(0);
		ASSERT_EQ(sipb::bye(wire, p), sipb::Err::Ok);
	}
	EXPECT_EQ(std::string_view(wire.bytes, wire.len),
		"BYE sip:100@192.168.31.10:1037;line=h2k6k1ih SIP/2.0\r\n"
		"Via: SIP/2.0/UDP 192.168.31.1:5060;branch=z9hG4bK0123456789AB\r\n"
		"From: <sip:106@server>;tag=ans106\r\n"
		"To: <sip:100@server>;tag=ftrc-bye-bytes\r\n"
		"Call-ID: rc-bye-bytes\r\n"
		"CSeq: 2 BYE\r\n"
		"Max-Forwards: 70\r\n"
		"Content-Length: 0\r\n"
		"\r\n");
}

// The same kill's second BYE, to the callee, which registered no Contact: the
// Request-URI is composed from the address it is sent to. Its branch is IDGen's
// second 16-byte block, hence the count starting at 16.
TEST(SipMessageBuilder, ByeIsMainsBytesForTheObservedAddress)
{
	sipb::ByeParams p{};
	p.targetUser = "106";
	p.destIp = "192.168.31.20";
	p.destPort = 5062;
	p.localIp = "192.168.31.1";
	p.localPort = 5060;
	p.from = "From: <sip:100@server>;tag=ftrc-bye-bytes";
	p.to = "To: <sip:106@server>;tag=ans106";
	p.callId = "Call-ID: rc-bye-bytes";
	p.cseq = 2;

	sipb::ByeWire wire;
	{
		CountingIds ids(16);
		ASSERT_EQ(sipb::bye(wire, p), sipb::Err::Ok);
	}
	EXPECT_EQ(std::string_view(wire.bytes, wire.len),
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

TEST(SipMessageBuilder, ByeAllocatesZeroHeap)
{
	// Positive control: the counter moves on a new whose pointer escapes.
	{
		static void* volatile sink = nullptr;
		AllocGuard positiveControl;
		int* p = new int(1234);
		sink = p;
		const size_t n = positiveControl.delta();
		delete p;
		EXPECT_GT(n, 0u);
	}

	const sipb::ByeParams params = validBye();
	sipb::ByeWire wire;
	AllocGuard guard;
	const sipb::Err err = sipb::bye(wire, params);
	const size_t allocs = guard.delta();

	EXPECT_EQ(err, sipb::Err::Ok);
	EXPECT_EQ(allocs, 0u) << "sipb::bye must never touch the heap";
}

// The worst case kMaxByeBytes is sized from, field for field as its comment
// lists them, so the 820 B written there cannot go stale.
TEST(SipMessageBuilder, ByeWorstCaseIs820Bytes)
{
	const std::string contact = "sip:" + std::string(128 - 4, 'u');
	const std::string from(200, 'f');
	const std::string to(200, 't');
	const std::string callId(125, 'c');
	sipb::ByeParams p = validBye();
	p.requestUri = contact;
	p.localIp = "255.255.255.255";
	p.localPort = 65535;
	p.from = from;
	p.to = to;
	p.callId = callId;
	p.cseq = 4294967295u;

	sipb::ByeWire wire;
	ASSERT_EQ(sipb::bye(wire, p), sipb::Err::Ok);
	EXPECT_EQ(wire.len, 820u);
	EXPECT_LT(wire.len, sipb::kMaxByeBytes);
	EXPECT_NE(std::string_view(wire.bytes, wire.len).find("\r\nCSeq: 4294967295 BYE\r\n"), std::string_view::npos);
}

// The cap itself: a BYE of kMaxByeBytes - 1 bytes is sent, one byte more is
// Truncated with len 0. The From value grows; it is written straight to the
// wire, with no smaller buffer in between to overflow first.
TEST(SipMessageBuilder, ByeCapBoundaryIs831Bytes)
{
	sipb::ByeParams p = validBye();
	sipb::ByeWire wire;
	ASSERT_EQ(sipb::bye(wire, p), sipb::Err::Ok);
	const size_t base = wire.len;
	ASSERT_LT(base, sipb::kMaxByeBytes - 1);

	std::string from(p.from);
	from.append(sipb::kMaxByeBytes - 1 - base, 'x');
	p.from = from;
	ASSERT_EQ(sipb::bye(wire, p), sipb::Err::Ok);
	EXPECT_EQ(wire.len, sipb::kMaxByeBytes - 1) << "831 B must fit";
	EXPECT_EQ(wire.len, 831u);

	from.push_back('x');
	p.from = from;
	EXPECT_EQ(sipb::bye(wire, p), sipb::Err::Truncated);
	EXPECT_EQ(wire.len, 0u) << "832 B must not fit, and len must be 0";
}

// Every caller-supplied field the BYE writes: an empty one, or one holding a
// byte that would end its line (and let the rest of the value inject a header),
// is BadField with len 0. A CRLF ending a "Name: value" line is the line's own
// and is dropped, as stripHeaderName() always did; one inside the value is not.
TEST(SipMessageBuilder, ByeRefusesAnEmptyFieldOrAByteThatEndsItsLine)
{
	using Field = std::string_view sipb::ByeParams::*;
	const std::string nul1("sip:a\0b", 7);
	const std::string nul2("<sip:a@b>\0", 10);
	const std::vector<std::pair<Field, std::string>> bad = {
		{&sipb::ByeParams::requestUri, "sip:a\r\nVia: x"},
		{&sipb::ByeParams::requestUri, "sip:a b"},
		{&sipb::ByeParams::requestUri, "sip:a\tb"},
		{&sipb::ByeParams::requestUri, nul1},
		{&sipb::ByeParams::requestUri, "sip:a\x7f"},
		{&sipb::ByeParams::localIp, ""},
		{&sipb::ByeParams::localIp, "192.168.31.1\r\nX: y"},
		{&sipb::ByeParams::localIp, "192.168.31.1 "},
		{&sipb::ByeParams::callId, ""},
		{&sipb::ByeParams::callId, "Call-ID: "},
		{&sipb::ByeParams::callId, "Call-ID: c1\r\nX-Injected: 1"},
		{&sipb::ByeParams::callId, "c1 @host"},
		{&sipb::ByeParams::from, ""},
		{&sipb::ByeParams::from, "From: "},
		{&sipb::ByeParams::from, "From: <sip:106@server>\r\nX-Injected: 1"},
		{&sipb::ByeParams::from, "<sip:106@server>\n;tag=1"},
		{&sipb::ByeParams::from, nul2},
		{&sipb::ByeParams::from, "<sip:106@server>\x7f"},
		{&sipb::ByeParams::to, ""},
		{&sipb::ByeParams::to, "To: <sip:100@server>\r\nX-Injected: 1"},
		{&sipb::ByeParams::to, "<sip:100@server>\r"},
		{&sipb::ByeParams::to, "<sip:100@server>\x01"},
	};
	for (const auto& [field, value] : bad)
	{
		SCOPED_TRACE(value);
		sipb::ByeParams p = validBye();
		p.*field = value;
		sipb::ByeWire wire;
		wire.len = 123;
		EXPECT_EQ(sipb::bye(wire, p), sipb::Err::BadField);
		EXPECT_EQ(wire.len, 0u);
	}

	// The composed Request-URI's parts, when no Contact was registered.
	const std::vector<std::pair<Field, std::string>> badParts = {
		{&sipb::ByeParams::targetUser, ""},
		{&sipb::ByeParams::targetUser, "100\r\nVia: x"},
		{&sipb::ByeParams::targetUser, "1 00"},
		{&sipb::ByeParams::destIp, ""},
		{&sipb::ByeParams::destIp, "192.168.31.10\n"},
	};
	for (const auto& [field, value] : badParts)
	{
		SCOPED_TRACE(value);
		sipb::ByeParams p = validBye();
		p.requestUri = {};
		p.*field = value;
		sipb::ByeWire wire;
		wire.len = 123;
		EXPECT_EQ(sipb::bye(wire, p), sipb::Err::BadField);
		EXPECT_EQ(wire.len, 0u);
	}
}

// What a From or To may hold, and main sent: a quoted display name's spaces and
// tabs, UTF-8, and a whole header line with its CRLF.
TEST(SipMessageBuilder, ByeKeepsDisplayNameSpacesAndUtf8)
{
	sipb::ByeParams p = validBye();
	p.from = "From: \"Front Desk\" <sip:106@server>;tag=ans106\r\n";
	p.to = "\"Jos\xc3\xa9\tM\xc3\xbcller\" <sip:100@server>;tag=ft1";
	sipb::ByeWire wire;
	ASSERT_EQ(sipb::bye(wire, p), sipb::Err::Ok);
	const std::string_view raw(wire.bytes, wire.len);
	EXPECT_NE(raw.find("\r\nFrom: \"Front Desk\" <sip:106@server>;tag=ans106\r\nTo: "), std::string_view::npos) << raw;
	EXPECT_NE(raw.find("\r\nTo: \"Jos\xc3\xa9\tM\xc3\xbcller\" <sip:100@server>;tag=ft1\r\nCall-ID: "),
		std::string_view::npos) << raw;
}
