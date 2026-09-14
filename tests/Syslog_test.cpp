// Syslog_test.cpp — issue #183: the RFC 5424 syslog-over-UDP sink.
//
// These tests drive the PURE FORMATTER, not a socket. src/Helpers/Syslog.cpp
// keeps the UDP send behind the ESP guard (see Syslog.hpp's layering note, and
// src/SIP/RtpReceiver.hpp:21-27 for the same convention), so there is nothing to
// listen for off-device — and that is the better seam anyway: every RFC 5424
// rule is a property of the bytes, and asserting the bytes directly is both
// exact and immune to the fixed-port collisions a loopback listener brings when
// two host runs overlap (drawbridge's copy binds 15514).
//
// The load-bearing test here is FieldOrderIsRfc5424: it splits the frame and
// asserts each header field BY INDEX. A syslog frame with a field in the wrong
// slot is still a syntactically valid frame — the collector parses it happily
// and files the data under the wrong name — so a "does it look right" assertion
// cannot catch the defect. drawbridge's version of this module has exactly that
// bug (the caller's app name lands in PROCID); this test is what stops the port
// from inheriting it.

#include <gtest/gtest.h>
#include "Syslog.hpp"

#include <string>
#include <vector>

namespace
{
	// RFC 5424 §6 header field positions, once, by name.
	enum HeaderField
	{
		kPriVersion     = 0,
		kTimestamp      = 1,
		kHostname       = 2,
		kAppName        = 3,
		kProcId         = 4,
		kMsgId          = 5,
		kStructuredData = 6,
		kHeaderFields   = 7,
	};

	struct ParsedFrame
	{
		std::vector<std::string> header;   // the seven fields above
		std::string              msg;      // everything after them
		bool                     wellFormed = false;
	};

	// Split on the SEVEN structural spaces only: MSG (§6.4) is free text and may
	// contain spaces of its own, so a naive whole-string split would mis-report a
	// multi-word message as extra header fields.
	ParsedFrame parseFrame(const std::string& frame)
	{
		ParsedFrame out;
		size_t pos = 0;
		for (int i = 0; i < kHeaderFields; ++i)
		{
			const size_t sp = frame.find(' ', pos);
			if (sp == std::string::npos)
			{
				// Running out of spaces is only legal on the last header field:
				// §6 makes MSG optional, so a frame may end at STRUCTURED-DATA.
				out.header.push_back(frame.substr(pos));
				out.wellFormed = (i == kStructuredData);
				return out;
			}
			out.header.push_back(frame.substr(pos, sp - pos));
			pos = sp + 1;
		}
		out.msg        = frame.substr(pos);
		out.wellFormed = true;
		return out;
	}
}

// ── PRI arithmetic (RFC 5424 §6.2.1) ─────────────────────────────────────────
// PRI = facility * 8 + severity, decimal, wrapped in angle brackets, with no
// leading zeros. The boundaries matter more than the typical case: <0> is the
// bottom of the range and <191> the top, and an off-by-one in either direction
// makes the collector file the line at the wrong urgency.
TEST(Syslog, PriIsFacilityTimesEightPlusSeverity)
{
	// local0(16) * 8 + info(6) = 134 — the value the device emits by default.
	EXPECT_EQ(Syslog::priValue(Syslog::Facility::Local0, Syslog::Severity::Info), 134);
	// local0 * 8 + err(3) = 131, warning(4) = 132.
	EXPECT_EQ(Syslog::priValue(Syslog::Facility::Local0, Syslog::Severity::Error), 131);
	EXPECT_EQ(Syslog::priValue(Syslog::Facility::Local0, Syslog::Severity::Warning), 132);
	// Top of the range this module can produce: local7(23) * 8 + debug(7) = 191.
	EXPECT_EQ(Syslog::priValue(Syslog::Facility::Local7, Syslog::Severity::Debug), 191);
	// user(1) * 8 + emerg(0) = 8; daemon(3) * 8 + crit(2) = 26.
	EXPECT_EQ(Syslog::priValue(Syslog::Facility::User, Syslog::Severity::Emergency), 8);
	EXPECT_EQ(Syslog::priValue(Syslog::Facility::Daemon, Syslog::Severity::Critical), 26);
}

// The arithmetic above has to reach the wire: PRI and VERSION share the first
// token with no space between them ("<134>1", not "<134> 1").
TEST(Syslog, PriAndVersionAreOneTokenAndVersionIsOne)
{
	const std::string frame = Syslog::formatFrame(
		Syslog::Severity::Info, Syslog::Facility::Local0, "pbx-call", "x=1");
	const ParsedFrame parsed = parseFrame(frame);
	ASSERT_TRUE(parsed.wellFormed) << frame;
	EXPECT_EQ(parsed.header[kPriVersion], "<134>1") << frame;

	const std::string top = Syslog::formatFrame(
		Syslog::Severity::Debug, Syslog::Facility::Local7, "pbx-log", "x=1");
	EXPECT_EQ(parseFrame(top).header[kPriVersion], "<191>1") << top;

	const std::string bottom = Syslog::formatFrame(
		Syslog::Severity::Emergency, Syslog::Facility::User, "pbx-log", "x=1");
	EXPECT_EQ(parseFrame(bottom).header[kPriVersion], "<8>1") << bottom;
}

// ── TIMESTAMP is the NILVALUE, deliberately (RFC 5424 §6.2.3) ────────────────
// This device initialises no SNTP client (the only SNTP call in the tree is
// esp_sntp_restart() at src/SIP/DtmfFeatureCodes.cpp:123, restarting a client
// nothing ever started — issue #194's prerequisite). §6.2.3 permits "-" exactly
// for an originator with no reliable clock, and the collector then stamps its
// own receive time. This test exists so that a later "helpful" change cannot
// quietly substitute a 1970 timestamp from an unset clock, which would be a lie
// the collector has no way to detect.
TEST(Syslog, TimestampIsNilValueBecauseThereIsNoWallClock)
{
	const std::string frame = Syslog::formatFrame(
		Syslog::Severity::Info, Syslog::Facility::Local0, "pbx-call", "caller=310");
	const ParsedFrame parsed = parseFrame(frame);
	ASSERT_TRUE(parsed.wellFormed) << frame;
	EXPECT_EQ(parsed.header[kTimestamp], "-") << frame;
	// And nothing that looks like an RFC 3339 stamp leaked in anywhere else.
	EXPECT_EQ(frame.find("1970-"), std::string::npos) << frame;
	EXPECT_EQ(frame.find('T'), std::string::npos) << frame;
}

// ── Field ordering (RFC 5424 §6.2) ───────────────────────────────────────────
// HEADER = PRI VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID,
// then SP STRUCTURED-DATA [SP MSG]. Seven header tokens: two NILVALUEs before
// APP-NAME and THREE after it.
TEST(Syslog, FieldOrderIsRfc5424)
{
	const std::string msg   = "caller=310 callee=210 duration=45 result=answered";
	const std::string frame = Syslog::formatFrame(
		Syslog::Severity::Info, Syslog::Facility::Local0, "pbx-call", msg.c_str());

	const ParsedFrame parsed = parseFrame(frame);
	ASSERT_TRUE(parsed.wellFormed) << frame;
	ASSERT_EQ(parsed.header.size(), static_cast<size_t>(kHeaderFields)) << frame;

	EXPECT_EQ(parsed.header[kPriVersion],     "<134>1")   << frame;
	EXPECT_EQ(parsed.header[kTimestamp],      "-")        << frame;
	EXPECT_EQ(parsed.header[kHostname],       "-")        << frame;
	EXPECT_EQ(parsed.header[kAppName],        "pbx-call") << frame;  // NOT PROCID
	EXPECT_EQ(parsed.header[kProcId],         "-")        << frame;
	EXPECT_EQ(parsed.header[kMsgId],          "-")        << frame;
	EXPECT_EQ(parsed.header[kStructuredData], "-")        << frame;
	EXPECT_EQ(parsed.msg, msg) << frame;

	// The whole frame, spelled out once, so a diff on this file shows the wire
	// format changing rather than only an index moving.
	EXPECT_EQ(frame, "<134>1 - - pbx-call - - - " + msg);
}

// ── APP-NAME (RFC 5424 §6.2.5): 1-48 PRINTUSASCII, or the NILVALUE ───────────
TEST(Syslog, AppNameIsNilValueWhenUnknown)
{
	EXPECT_EQ(parseFrame(Syslog::formatFrame(
		Syslog::Severity::Info, Syslog::Facility::Local0, "", "x=1")).header[kAppName], "-");
	EXPECT_EQ(parseFrame(Syslog::formatFrame(
		Syslog::Severity::Info, Syslog::Facility::Local0, nullptr, "x=1")).header[kAppName], "-");
}

// A space (or a control byte) inside APP-NAME would be read as a field
// separator and shift every later field one slot left, so it must never reach
// the wire — that is a parse corruption, not a cosmetic issue.
TEST(Syslog, AppNameIsSanitizedSoItCannotShiftTheFields)
{
	const std::string frame = Syslog::formatFrame(
		Syslog::Severity::Info, Syslog::Facility::Local0, "pbx call\tx", "x=1");
	const ParsedFrame parsed = parseFrame(frame);
	ASSERT_TRUE(parsed.wellFormed) << frame;
	EXPECT_EQ(parsed.header[kAppName], "pbx_call_x") << frame;
	// The fields after it are still where they belong.
	EXPECT_EQ(parsed.header[kProcId],         "-") << frame;
	EXPECT_EQ(parsed.header[kStructuredData], "-") << frame;
	EXPECT_EQ(parsed.msg, "x=1") << frame;
}

TEST(Syslog, AppNameIsCappedAt48Bytes)
{
	const std::string longName(80, 'a');
	const ParsedFrame parsed = parseFrame(Syslog::formatFrame(
		Syslog::Severity::Info, Syslog::Facility::Local0, longName.c_str(), "x=1"));
	ASSERT_TRUE(parsed.wellFormed);
	EXPECT_EQ(parsed.header[kAppName].size(), Syslog::kMaxAppNameBytes);
	EXPECT_EQ(parsed.header[kAppName], std::string(48, 'a'));
}

// ── MSG (RFC 5424 §6.4) ──────────────────────────────────────────────────────
// MSG is optional: with nothing to say the frame legally ends at
// STRUCTURED-DATA, and must not carry a dangling separator.
TEST(Syslog, EmptyMessageEndsTheFrameAtStructuredData)
{
	const std::string frame = Syslog::formatFrame(
		Syslog::Severity::Warning, Syslog::Facility::Local0, "pbx-register", "");
	EXPECT_EQ(frame, "<132>1 - - pbx-register - - -");
	EXPECT_NE(frame.back(), ' ');

	const std::string nullMsg = Syslog::formatFrame(
		Syslog::Severity::Warning, Syslog::Facility::Local0, "pbx-register", nullptr);
	EXPECT_EQ(nullMsg, frame);
}

// One datagram IS one syslog message (RFC 5426 §3.1), so the trailing newline
// the ESP log drain hands over (LogQueue.hpp:114 writes whole log lines) carries
// no framing information and only upsets line-oriented collectors.
TEST(Syslog, TrailingNewlineIsTrimmedFromTheMessage)
{
	const std::string frame = Syslog::formatFrame(
		Syslog::Severity::Info, Syslog::Facility::Local0, "pbx-log", "sip: REGISTER ok\r\n");
	EXPECT_EQ(frame, "<134>1 - - pbx-log - - - sip: REGISTER ok");
	// Interior spaces are untouched — MSG is free text.
	EXPECT_NE(frame.find("REGISTER ok"), std::string::npos);
}

// ── Buffer form: the zero-alloc path send() actually uses ────────────────────
TEST(Syslog, BufferFormMatchesStringFormAndReportsWireLength)
{
	char buf[Syslog::kMaxFrameBytes];
	const size_t n = Syslog::formatFrame(buf, sizeof(buf),
		Syslog::Severity::Error, Syslog::Facility::Local0, "pbx-call", "result=failed");
	const std::string expected = Syslog::formatFrame(
		Syslog::Severity::Error, Syslog::Facility::Local0, "pbx-call", "result=failed");

	EXPECT_EQ(std::string(buf, n), expected);
	EXPECT_EQ(n, expected.size());      // returned length excludes the NUL
	EXPECT_EQ(buf[n], '\0');
}

// Truncation must cost only the tail of MSG: the header is bounded at 65 bytes,
// so a short buffer still yields something a collector can parse.
TEST(Syslog, TruncationKeepsTheHeaderAndNulTerminates)
{
	char buf[40];
	const std::string longMsg(200, 'z');
	const size_t n = Syslog::formatFrame(buf, sizeof(buf),
		Syslog::Severity::Info, Syslog::Facility::Local0, "pbx-log", longMsg.c_str());

	ASSERT_LT(n, sizeof(buf));
	EXPECT_EQ(buf[n], '\0');
	EXPECT_EQ(std::string(buf, n).rfind("<134>1 - - pbx-log - - - ", 0), 0u) << buf;

	// A zero-capacity call writes nothing and reports nothing (no deref of out).
	EXPECT_EQ(Syslog::formatFrame(buf, 0, Syslog::Severity::Info,
		Syslog::Facility::Local0, "pbx-log", "x"), 0u);
	EXPECT_EQ(Syslog::formatFrame(nullptr, 16, Syslog::Severity::Info,
		Syslog::Facility::Local0, "pbx-log", "x"), 0u);
}

// ── Sink lifecycle ───────────────────────────────────────────────────────────
// Off-device configure() validates and accepts a destination but nothing is
// emitted (Syslog.hpp's layering note) — so these assert the state machine and
// the address validation, which are platform-independent, not delivery.
TEST(Syslog, SinkIsDisabledUntilConfiguredAndSendIsANoOp)
{
	ASSERT_TRUE(Syslog::configure(""));   // explicit, so test ordering cannot matter
	EXPECT_FALSE(Syslog::isConfigured());
	// Must not crash, throw, or touch a socket when there is no destination.
	Syslog::send(Syslog::Severity::Info, "pbx-test", "dropped silently");
	Syslog::send(Syslog::Severity::Info, std::string("pbx-test"), std::string("also dropped"));
}

TEST(Syslog, ConfigureAcceptsOnlyADottedQuad)
{
	// No DNS by design: a name would need a blocking resolver on the hot path.
	EXPECT_FALSE(Syslog::configure("syslog.example.com"));
	EXPECT_FALSE(Syslog::isConfigured());

	EXPECT_FALSE(Syslog::configure("192.168.1"));        // short form
	EXPECT_FALSE(Syslog::configure("192.168.1.1.1"));    // too many octets
	EXPECT_FALSE(Syslog::configure("192.168.1.256"));    // octet out of range
	EXPECT_FALSE(Syslog::configure("192.168.01.1"));     // leading zero reads as octal
	EXPECT_FALSE(Syslog::configure(" 192.168.1.1"));     // whitespace
	EXPECT_FALSE(Syslog::configure("192.168.1.1:514"));  // port suffix
	EXPECT_FALSE(Syslog::configure("::1"));              // IPv6 is not supported
	EXPECT_FALSE(Syslog::isConfigured());

	EXPECT_TRUE(Syslog::configure("192.168.1.10", 514));
	EXPECT_TRUE(Syslog::isConfigured());
	EXPECT_TRUE(Syslog::configure("0.0.0.0"));           // legal quad, odd choice
	EXPECT_TRUE(Syslog::configure("255.255.255.255"));   // broadcast, still legal

	ASSERT_TRUE(Syslog::configure(""));                  // leave the sink clean
	EXPECT_FALSE(Syslog::isConfigured());
}

TEST(Syslog, EmptyHostDisablesTheSink)
{
	ASSERT_TRUE(Syslog::configure("10.0.0.5", 1514));
	ASSERT_TRUE(Syslog::isConfigured());
	ASSERT_TRUE(Syslog::configure(""));   // disabling is a success, not a failure
	EXPECT_FALSE(Syslog::isConfigured());

	// A rejected host also leaves the sink off rather than keeping the old one.
	ASSERT_TRUE(Syslog::configure("10.0.0.5"));
	ASSERT_FALSE(Syslog::configure("not-an-ip"));
	EXPECT_FALSE(Syslog::isConfigured());
}
