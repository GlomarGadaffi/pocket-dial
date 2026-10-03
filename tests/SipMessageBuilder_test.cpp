// SipMessageBuilder_test.cpp — bounded, zero-heap SIP message builder (RFC 3261).
// Part of Issue #744 (strangler plan: builder track B1).

#include <gtest/gtest.h>

#include <cstring>
#include <string>
#include <string_view>

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
	sipb::Wire wire{};
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
	// Positive control: verify that AllocGuard is active and increments on new
	{
		AllocGuard positiveControl;
		volatile auto* p = new int(1234);
		EXPECT_GT(positiveControl.delta(), 0u);
		delete p;
	}

	sipb::Wire wire{};
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
	sipb::Wire wire{};
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

// B1: the random identifiers come from IDGen's CSPRNG path and nothing else
// (#385). A local PRNG would ignore the injected byte source and fail this.
TEST(SipMessageBuilder, OptionsIdsComeFromIdGen)
{
	IDGen::setByteSourceForTest([](uint8_t* buf, size_t len) {
		for (size_t i = 0; i < len; ++i) buf[i] = 1;   // 0x01 -> alphabet[1] == '1'
	});
	sipb::Wire wire{};
	const sipb::Err err = sipb::options(wire, "101", "192.168.1.50", 5060, "192.168.1.1", 5060);
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
	sipb::Wire wire{};
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
	sipb::Wire wire{};
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
