#ifndef SDP_HPP
#define SDP_HPP

#include <cstddef>
#include <cstdint>
#include <string_view>
#include <type_traits>

#include "SipMessage.hpp"   // SdpLimits

// ── RFC 8866 SDP model ───────────────────────────────────────────────────────
//
// A flat, fixed-capacity, offset-only description of one SDP body (issue #196).
// It replaces SipSdpMessage's six-FieldSpan cache, which could answer only six
// questions about a body and got two of them wrong in the presence of
// media-level lines.
//
// Three properties define this file, and each one exists because of a specific
// failure:
//
//   OFFSETS, NEVER POINTERS. Every field is a `Span` of byte offsets into the
//   body, resolved against the OWNING message at read time. SipMessage is
//   copyable by design and the message pool recycles slots with `*msg = source`
//   (RequestsHandler.cpp), so a cached string_view or pointer would be copied
//   verbatim and left aimed at the SOURCE message's body -- dangling the moment
//   that slot is reused. A static_assert at the bottom of this header enforces
//   trivial copyability so the property cannot be lost by accident.
//
//   FIXED CAPACITY, FAIL CLOSED. No std::vector, no std::string, no allocation.
//   Overflowing a cap is a hard parse failure returned as an SdpVerdict, not a
//   silently truncated parse -- see the note on fail-closed below, which is a
//   deliberate trade rather than an oversight.
//
//   WORK BOUNDED BY BYTES, NOT BY STRUCTURE. The threat model is CWE-674: the
//   UNISOC T612 VoLTE RCE was uncontrolled recursion in an `a=acap` decoder,
//   where a body of repeated `acap:1 acap:1 ...` drove one recursion per token
//   until the modem stack overflowed into a neighbouring task. Nothing here
//   recurses and nothing here nests: sections and attributes are flat arrays
//   with compile-time caps, so total work is bounded by
//   kMaxLines x kMaxLineBytes regardless of what the bytes say.
//
// ── Fail closed, and what it costs ───────────────────────────────────────────
//
// The 33rd attribute in a section or the 5th m= section is a hard failure that
// propagates to a 488 on the same path checkSdp() already uses. It is NOT
// counted-and-ignored. The cost is real and worth stating plainly: an
// ICE/DTLS-heavy WebRTC offer, which routinely runs 20-30 attributes per
// section, gets refused rather than relayed. This PBX serves hardphones and
// does no ICE, so that is acceptable today -- but kMaxAttributesPerSection is
// the single knob most likely to need raising in the field, which is why it is
// documented in SCALING.md rather than only here.

namespace sdp
{
	// Caps specific to the structured model. Deliberately a separate namespace
	// from SdpLimits (which bounds the WIRE body and is enforced by checkSdp()
	// before anything here runs) so it stays obvious which limit refused a body.
	namespace Limits
	{
		// Real offers this PBX sees: audio (1); audio+video (2); audio+video+
		// application/BFCP (3). RFC 3264 s8 requires an answer to carry the same
		// NUMBER of m= sections as the offer, and a re-offer may only ADD, so a
		// section must be preserved even when rejected with port 0. 4 gives one
		// section of slack over the worst realistic case.
		constexpr unsigned kMaxMediaSections = 4;

		// 32, not the 16 first proposed. A bare `pjsua --null-audio` with no codec
		// restriction -- which is exactly what tests/interop launches -- offers
		// pjsip's full default codec list, estimated at 18-20 a= lines in a single
		// audio section. A cap of 16 would fail-closed on our OWN interop harness.
		// The real number is measured and recorded in the PR rather than left as
		// an estimate. With borrowed scratch there is no per-message cost to 32.
		constexpr unsigned kMaxAttributesPerSection = 32;

		// Hardphones emit 0-3 session-level attributes; pjsua emits several more.
		constexpr unsigned kMaxSessionAttributes = 16;

		// Shares the wire cap: a body with more <fmt> tokens than this was already
		// refused by checkSdp(), so the model never has to represent one.
		constexpr unsigned kMaxFormats = SdpLimits::kMaxMediaFormats;
	}

	// A byte range in the owning message's body. len == 0 means ABSENT: every
	// line this model records starts with a two-character prefix, so a matched
	// span is never shorter than 2 and the sentinel is unambiguous.
	//
	// SPAN CONVENTION, and it is load-bearing: every LINE-level span covers the
	// WHOLE line INCLUDING its two-character prefix -- `version` is "v=0", not
	// "0", and `connection` is "c=IN IP4 ...". Only an Attribute's name/value
	// are sub-spans, because an a= line is the one kind that has to be taken
	// apart to be useful.
	//
	// Two reasons, and the first is not aesthetic. SipSdpMessage's six existing
	// accessors return whole lines today and their callers parse accordingly
	// (extractRtpPort() reads the port by finding the first space in
	// "m=audio 4000 ..."), so reimplementing them on a value-only model would
	// silently change what every existing caller sees. Second, verbatim relay
	// and re-serialisation want the bytes as they arrived.
	struct Span
	{
		uint32_t pos = 0;
		uint32_t len = 0;

		bool absent() const { return len == 0; }
	};

	// Resolve a span against a body. Clamps to the body's size rather than
	// trusting the offsets: a span that somehow outlived its body (the copied
	// pool-slot case this design exists to survive) then yields an in-bounds view
	// of THIS body, never a read past the end of it.
	std::string_view view(std::string_view body, Span s);

	// What an attribute IS, decided once by the lexer instead of by strcmp at
	// every use site. Keeping this in the model is what lets the direction lookup
	// and the offer/answer code branch on an enum rather than re-parsing text.
	enum class AttrKind : uint8_t
	{
		Unknown,    // malformed a= line; name holds the whole value, never interpreted
		Sendrecv,
		Sendonly,
		Recvonly,
		Inactive,
		Rtpmap,
		Fmtp,
		Ptime,
		Maxptime,
		Mid,
		Other,      // well-formed, recognised as an attribute, not one we act on
	};

	// Stream direction (RFC 8866 s6.7). Absent from a section means inherit the
	// session level, and absent from both means sendrecv (s6.7.4).
	enum class Direction : uint8_t { Sendrecv, Sendonly, Recvonly, Inactive };

	struct Attribute
	{
		Span     name;                 // "rtpmap"
		Span     value;                // "0 PCMU/8000"; absent for a property form
		AttrKind kind = AttrKind::Unknown;

		// Payload type parsed out of the value for rtpmap/fmtp only. 0xFF means
		// "not applicable or not numeric" -- kept here so filtering payload types
		// (issue #194 stage 4) never has to re-lex the value.
		//
		// THE 0xFF DEFAULT COSTS 6,640 BYTES OF FLASH, DELIBERATELY. It is a
		// non-zero initialiser, so the two static Session scratch slots in
		// SipSdpMessage.cpp cannot live in .bss and land in .data instead --
		// stored in the flash image and copied to DRAM at boot rather than
		// zero-filled. Measured: g_scratch is 0x19f0 in .data.
		//
		// Do NOT "fix" this by making the sentinel zero-valued. It buys flash
		// ONLY -- the DRAM cost is identical either way, because .bss occupies
		// the same memory -- and it costs either a pt-plus-one encoding every
		// reader has to decode, or a silent trap where an unset pt reads as 0,
		// which is PCMU: a VALID payload type rather than an obviously wrong
		// one. Removing that class of ambiguity is why this model exists.
		// Reviewed and accepted 2026-09-15.
		uint8_t  pt = 0xFF;
	};

	struct Media
	{
		Span     line;        // the whole m= line without CRLF, for verbatim relay
		Span     typeName;    // "audio"
		Span     proto;       // "RTP/AVP"
		uint16_t port = 0;    // 0 == stream rejected (RFC 3264 s6)
		uint8_t  portCount = 1;
		uint8_t  nFmt = 0;
		uint8_t  fmt[Limits::kMaxFormats] = {};   // payload numbers, in offer order

		Span connection;      // media-level c=; absent -> inherit Session::connection
		Span bandwidth;       // b=, stored and relayed, never interpreted
		Span key;             // k=, stored so relay is faithful; RFC 8866 s5.12
		                      // deprecates it and nothing here decodes it

		// A non-numeric <fmt> (RTP/SAVPF oddities). The section is preserved for
		// verbatim relay but cannot be answered, because choosing a payload type
		// out of it would be a guess.
		bool malformedFmt = false;

		uint8_t   nAttrs = 0;
		Attribute attrs[Limits::kMaxAttributesPerSection] = {};

		// Direction is deliberately NOT a stored field. It is "the last
		// direction-kind attribute in attrs[]", computed by a bounded scan. One
		// source of truth means a mutation cannot leave a cached direction
		// disagreeing with the attribute list that will actually be serialised.
	};

	struct Session
	{
		Span version, origin, name, connection, time, bandwidth, key;

		uint8_t   nAttrs = 0;
		Attribute attrs[Limits::kMaxSessionAttributes] = {};

		uint8_t nMedia = 0;
		Media   media[Limits::kMaxMediaSections] = {};

		uint16_t lines = 0;          // lines consumed, capped at SdpLimits::kMaxLines
		uint8_t  unknownLines = 0;   // not one of v/o/s/c/t/m/a/b/k/i/u/e/p/r/z
	};

	// Why a parse was refused. Anything other than Ok propagates to a 488 on the
	// wire path, alongside checkSdp()'s existing verdicts.
	enum class Verdict : uint8_t
	{
		Ok,
		TooManyMediaSections,      // a 5th m=
		TooManyAttributes,         // a 33rd a= in one section, or a 17th session-level
		TooManyLines,              // more than SdpLimits::kMaxLines
		LineTooLong,               // a line over SdpLimits::kMaxLineBytes
	};

	// Parse `body` into `out`. `out` is fully reset first: a field present in a
	// PREVIOUS body must never survive into this one, which is the recycled
	// pool-slot case that makes a stale cache dangerous rather than merely wrong.
	//
	// Non-recursive by construction. The implementation lives in Sdp.cpp,
	// generated from Sdp.re by re2c -- a switch/goto DFA in a single frame that
	// cannot call itself. tests/tools/check_parser_callgraph.py asserts that
	// mechanically rather than trusting this comment.
	Verdict parse(std::string_view body, Session& out);

	// The connection line that actually applies to a media section: its own c= if
	// it has one, otherwise the session-level c= (RFC 8866 s5.7). This is the
	// interop bug #196 item 2 names -- some phones emit c= ONLY per media, and a
	// reader that looked at the session level alone saw no connection address at
	// all.
	Span effectiveConnection(const Session& s, unsigned mediaIndex);

	// The direction that applies to a media section: its last direction-kind
	// attribute, else the session's, else sendrecv (RFC 8866 s6.7.4).
	Direction effectiveDirection(const Session& s, unsigned mediaIndex);

	// True when a section is held, by either the modern or the legacy signal:
	// direction in {sendonly, inactive}, or the RFC 2543 form where the
	// connection address is 0.0.0.0. Both are in the field.
	bool isHold(const Session& s, std::string_view body, unsigned mediaIndex);

	// The model must stay copyable by memcpy for the pool-slot argument above to
	// hold. If this ever fails, something grew a pointer, a reference, a
	// string_view or a non-trivial member -- and the dangling-reference class of
	// bug this whole design exists to prevent is back.
	static_assert(std::is_trivially_copyable_v<Span>,      "Span must stay trivially copyable");
	static_assert(std::is_trivially_copyable_v<Attribute>, "Attribute must stay trivially copyable");
	static_assert(std::is_trivially_copyable_v<Media>,     "Media must stay trivially copyable");
	static_assert(std::is_trivially_copyable_v<Session>,   "Session must stay trivially copyable");

	// SIZE IS A DESIGN CONSTRAINT HERE, not an implementation detail, so it is
	// asserted rather than remembered.
	//
	// MEASURED 2026-09-15 on x86-64: Span 8, Attribute 20, Media 728,
	// Session 3300 bytes. The original design estimated ~1.35 KB from a 12-byte
	// Attribute and 16 attributes per section; raising the cap to 32 (so our own
	// pjsua interop offer is not fail-closed) and Attribute padding to 20 rather
	// than 12 together more than doubled it, and nobody re-derived the number
	// after the cap change.
	//
	// That is exactly why this model is NOT stored per message. SipMessagePool
	// constructs all POCKETDIAL_MSG_POOL slots as SipSdpMessage, so an in-object
	// model would cost 52 x 3300 = ~168 KB of RAM on an ESP32-S3 -- not the
	// ~70 KB the estimate suggested, and not survivable. Two borrowed scratch
	// slots cost ~6.6 KB total instead.
	//
	// The bound below is deliberately loose enough to absorb ordinary field
	// additions and tight enough that another cap increase trips it and forces
	// the RAM arithmetic to be redone ON PURPOSE.
	static_assert(sizeof(Session) <= 4096,
		"sdp::Session grew past 4 KB. Two scratch slots are ~2x this. Redo the "
		"RAM arithmetic before raising a cap -- see the measurement above.");
}

#endif // SDP_HPP
