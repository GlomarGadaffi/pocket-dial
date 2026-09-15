// SdpModel_test.cpp — issue #196: the invariants the SDP model rests on, held
// at compile time wherever that is possible.
//
// Two of the three properties in Sdp.hpp's header comment are structural rather
// than behavioural, so they are asserted by the compiler and merely WITNESSED
// here. A runtime test cannot catch "someone added a std::string to Media" on
// the one build that matters; a static_assert can, on every build.
//
// The third property -- that parsing is bounded and non-recursive -- is not
// checkable from a test at all and is enforced by
// tests/tools/check_parser_callgraph.py against the generated Sdp.cpp.

#include <gtest/gtest.h>

#include <cstddef>
#include <type_traits>

#include "PoolConfig.hpp"
#include "Sdp.hpp"

// ── The pool-copy property ───────────────────────────────────────────────────
//
// SipMessage is copyable by design and the pool recycles slots with
// `*msg = source`. Every field in the model is a byte offset for that reason:
// a pointer or a string_view would survive the copy still aimed at the SOURCE
// message's body and dangle the moment that slot is reused. These mirror the
// asserts in Sdp.hpp so a failure names the reason, not just the line.
static_assert(std::is_trivially_copyable_v<sdp::Session>,
	"sdp::Session must be memcpy-safe: the message pool copies model-bearing "
	"objects, and a non-trivial member means something holds a reference.");
static_assert(std::is_trivially_copyable_v<sdp::Media>,      "see above");
static_assert(std::is_trivially_copyable_v<sdp::Attribute>,  "see above");
static_assert(std::is_trivially_copyable_v<sdp::Span>,       "see above");

// ── The RAM property that chose borrowed scratch ─────────────────────────────
//
// SipMessagePool constructs ALL POCKETDIAL_MSG_POOL slots as SipSdpMessage
// (SipMessagePool.cpp), so an in-object model is paid 52 times over. Measured
// 2026-09-15: Session is 3300 bytes, i.e. ~168 KB in-object against ~6.6 KB for
// two shared scratch slots. The original design estimated ~70 KB from a 12-byte
// Attribute and a 16-attribute cap; raising the cap to 32 and Attribute padding
// to 20 more than doubled it, and nobody re-derived it after the cap change.
static_assert(sizeof(sdp::Session) * POCKETDIAL_MSG_POOL > 64u * 1024u,
	"An in-object model would now fit comfortably in RAM. If that is really "
	"true, borrowed scratch may not be worth its complexity -- revisit the "
	"decision deliberately rather than deleting this assert.");

TEST(SdpModel, SpanAbsenceIsUnambiguous)
{
	// len == 0 is the ONLY absence sentinel. It is safe precisely because every
	// line the model records carries a two-character prefix, so a matched span is
	// never shorter than 2 -- there is no legitimate zero-length match to confuse
	// with "not present".
	sdp::Span none;
	EXPECT_TRUE(none.absent());

	sdp::Span present{10, 2};
	EXPECT_FALSE(present.absent());

	// pos alone never means present: a field at offset 0 with no length is still
	// absent, which matters because offset 0 is where `v=` lives.
	sdp::Span atZero{0, 0};
	EXPECT_TRUE(atZero.absent());
}

TEST(SdpModel, ViewClampsRatherThanReadingPastTheBody)
{
	// The defence that makes a stale span harmless. If a span somehow outlives
	// the body it was parsed from -- the copied pool-slot case this design exists
	// to survive -- resolving it must yield an in-bounds view of THIS body, never
	// a read past the end of it.
	const std::string_view body = "v=0\r\n";

	EXPECT_EQ(sdp::view(body, sdp::Span{0, 3}), "v=0");

	// Length running past the end: clamped, not truncated to empty and not read.
	EXPECT_EQ(sdp::view(body, sdp::Span{3, 999}).size(), body.size() - 3);

	// Position entirely past the end: empty, no read.
	EXPECT_TRUE(sdp::view(body, sdp::Span{9999, 4}).empty());

	// Absent stays empty regardless of position.
	EXPECT_TRUE(sdp::view(body, sdp::Span{2, 0}).empty());

	// An empty body cannot produce a non-empty view from any span.
	EXPECT_TRUE(sdp::view(std::string_view{}, sdp::Span{0, 10}).empty());
}

TEST(SdpModel, DefaultSessionIsEmptyNotGarbage)
{
	// A freshly constructed model must read as "nothing parsed" rather than as a
	// zero-length section list with live-looking spans. parse() resets before
	// filling for the same reason: a field from a PREVIOUS body must never
	// survive into this one.
	sdp::Session s{};
	EXPECT_EQ(s.nMedia, 0);
	EXPECT_EQ(s.nAttrs, 0);
	EXPECT_EQ(s.lines, 0);
	EXPECT_EQ(s.unknownLines, 0);
	EXPECT_TRUE(s.version.absent());
	EXPECT_TRUE(s.connection.absent());
	EXPECT_TRUE(s.origin.absent());
}
