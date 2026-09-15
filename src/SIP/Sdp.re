// Sdp.re — re2c source for the RFC 8866 SDP parser (issue #196).
//
// THIS FILE IS THE AUTHORITY. Sdp.cpp is generated from it and committed, so
// the firmware build never requires re2c; CI regenerates and diffs to catch
// drift. Never edit Sdp.cpp.
//
// Regenerate with EXACTLY:
//
//     re2c --no-generation-date --no-debug-info -W Sdp.re -o Sdp.cpp
//
// `--no-debug-info` is not optional and must not be removed to "get better
// diagnostics". Without it re2c emits #line directives carrying the ABSOLUTE
// path of this file, so output generated on one machine can never match output
// generated on another, and the CI drift check is red on every run forever.
// The cost is that compiler diagnostics and -fstack-usage numbers point at
// Sdp.cpp lines rather than at this file; that is the price of a reproducible
// committed artifact.
//
// re2c stamps its own version on line 1 of the output, so a version mismatch
// between a developer and CI shows up as a one-line diff at the top of the
// drift check rather than as a subtle behavioural difference buried in a DFA.
//
// ── Why re2c at all ──────────────────────────────────────────────────────────
//
// The threat model is CWE-674, the UNISOC T612 VoLTE RCE: uncontrolled
// recursion in an `a=acap` decoder, where a body of repeated `acap:1 acap:1 …`
// drove one recursion per token until the modem stack overflowed into a
// neighbouring task. re2c emits a switch/goto DFA — one function frame, fixed
// locals, no self-call and no call back into the driver. It cannot recurse, and
// that is a property of the generator rather than of anyone's discipline.
// tests/tools/check_parser_callgraph.py asserts it mechanically against the
// generated file.
//
// Every loop below is bounded by a byte count or a compile-time cap, never by
// nesting: the driver runs at most SdpLimits::kMaxLines iterations, each lexer
// advances monotonically to the end of one line, and every array is fixed. Total
// work is bounded by kMaxLines × kMaxLineBytes no matter what the bytes say.
//
// The body is NOT NUL-terminated (it is a view into a SipMessage), so the
// NUL-sentinel pattern would read past the end. Every block below uses
// `re2c:eof = 0` with an explicit YYLIMIT, which makes re2c bounds-check each
// peek.

#include "Sdp.hpp"

#include <cstring>

namespace sdp
{
namespace
{

// Which SDP line type a line starts with. RFC 8866 §5.
enum class LineTag : uint8_t
{
	V, O, S, C, T, M, A, B, K,
	Ignored,   // i= u= e= p= r= z= — legal, carried by nothing we model
	Empty,
	Unknown,   // counted, never fatal
};

// ── Lexer 1: line type ───────────────────────────────────────────────────────
//
// Matches only the two-character prefix. The remainder of the line is the
// value and is handed on as a span; there is nothing to gain from having the
// DFA walk bytes the caller already knows the extent of.
LineTag lexLineType(const char* YYCURSOR, const char* YYLIMIT)
{
/*!re2c
	re2c:define:YYCTYPE = char;
	re2c:yyfill:enable  = 0;
	re2c:eof            = 0;

	"v=" { return LineTag::V; }
	"o=" { return LineTag::O; }
	"s=" { return LineTag::S; }
	"c=" { return LineTag::C; }
	"t=" { return LineTag::T; }
	"m=" { return LineTag::M; }
	"a=" { return LineTag::A; }
	"b=" { return LineTag::B; }
	"k=" { return LineTag::K; }

	"i=" | "u=" | "e=" | "p=" | "r=" | "z=" { return LineTag::Ignored; }

	$ { return LineTag::Empty; }
	* { return LineTag::Unknown; }
*/
}

// ── Lexer 2: attribute name → kind ───────────────────────────────────────────
//
// Run on the NAME span only. Each rule re-checks that the match consumed the
// whole span, so "sendrecvX" is Other rather than Sendrecv — a prefix match
// would let a nonsense attribute silently change a stream's direction.
AttrKind lexAttrKind(const char* YYCURSOR, const char* YYLIMIT)
{
	const char* const end = YYLIMIT;
	// The keyword set has overlapping prefixes (ptime / maxptime, sendrecv /
	// sendonly), so the DFA backtracks and re2c needs a marker to rewind to.
	const char* YYMARKER = YYCURSOR;
/*!re2c
	re2c:define:YYCTYPE = char;
	re2c:yyfill:enable  = 0;
	re2c:eof            = 0;

	"sendrecv" { return (YYCURSOR == end) ? AttrKind::Sendrecv : AttrKind::Other; }
	"sendonly" { return (YYCURSOR == end) ? AttrKind::Sendonly : AttrKind::Other; }
	"recvonly" { return (YYCURSOR == end) ? AttrKind::Recvonly : AttrKind::Other; }
	"inactive" { return (YYCURSOR == end) ? AttrKind::Inactive : AttrKind::Other; }
	"rtpmap"   { return (YYCURSOR == end) ? AttrKind::Rtpmap   : AttrKind::Other; }
	"fmtp"     { return (YYCURSOR == end) ? AttrKind::Fmtp     : AttrKind::Other; }
	"ptime"    { return (YYCURSOR == end) ? AttrKind::Ptime    : AttrKind::Other; }
	"maxptime" { return (YYCURSOR == end) ? AttrKind::Maxptime : AttrKind::Other; }
	"mid"      { return (YYCURSOR == end) ? AttrKind::Mid      : AttrKind::Other; }

	$ { return AttrKind::Other; }
	* { return AttrKind::Other; }
*/
}

// ── Lexer 3: leading payload type of an rtpmap/fmtp value ────────────────────
//
// "0 PCMU/8000" → 0. Returns 0xFF when the value does not begin with a 1-3
// digit number followed by a separator, which is the honest answer for a value
// we cannot attribute to a payload type.
uint8_t lexLeadingPt(const char* YYCURSOR, const char* YYLIMIT)
{
	const char* const start = YYCURSOR;
	const char* const end   = YYLIMIT;
/*!re2c
	re2c:define:YYCTYPE = char;
	re2c:yyfill:enable  = 0;
	re2c:eof            = 0;

	[0-9]{1,3} {
		const size_t n = static_cast<size_t>(YYCURSOR - start);
		// Must be followed by a separator or the end of the value: "1234" is not
		// payload type 123 with a stray digit.
		if (YYCURSOR != end && *YYCURSOR != ' ' && *YYCURSOR != '/' && *YYCURSOR != '\t')
		{
			return 0xFF;
		}
		unsigned v = 0;
		for (size_t i = 0; i < n; ++i) v = v * 10u + static_cast<unsigned>(start[i] - '0');
		// RFC 3550 caps the payload type at 7 bits; 0xFF is our sentinel, so a
		// value that cannot be one is reported as absent rather than truncated.
		return (v <= 127u) ? static_cast<uint8_t>(v) : 0xFF;
	}

	$ { return 0xFF; }
	* { return 0xFF; }
*/
}

// Span covering [base, p) offsets within the whole body.
inline Span spanOf(const char* bodyBegin, const char* b, const char* e)
{
	Span s;
	s.pos = static_cast<uint32_t>(b - bodyBegin);
	s.len = static_cast<uint32_t>(e - b);
	return s;
}

// Split an a= line value into name and optional value at the FIRST ':'.
// Bounded by the span length. Not a DFA because there is nothing to recognise —
// only a delimiter to find — and a DFA here would be ceremony, not safety.
void splitAttr(const char* b, const char* e, const char*& nameEnd, const char*& valBegin)
{
	nameEnd  = e;
	valBegin = e;
	for (const char* p = b; p != e; ++p)
	{
		if (*p == ':')
		{
			nameEnd  = p;
			valBegin = p + 1;
			return;
		}
	}
}

// Parse an m= line value: <type> SP <port>[/<count>] SP <proto> (SP <fmt>)*
// One forward pass, no backtracking, bounded by the line length.
void parseMediaLine(const char* bodyBegin, const char* b, const char* e, Media& m)
{
	const char* p = b;

	auto token = [&](const char*& ts, const char*& te) {
		while (p != e && *p == ' ') ++p;
		ts = p;
		while (p != e && *p != ' ') ++p;
		te = p;
		return ts != te;
	};

	const char *ts = nullptr, *te = nullptr;

	if (token(ts, te)) m.typeName = spanOf(bodyBegin, ts, te);

	if (token(ts, te))
	{
		unsigned port = 0, count = 0;
		const char* q = ts;
		bool sawDigit = false;
		while (q != te && *q >= '0' && *q <= '9') { port = port * 10u + static_cast<unsigned>(*q - '0'); ++q; sawDigit = true; }
		if (sawDigit) m.port = (port <= 65535u) ? static_cast<uint16_t>(port) : 0;
		if (q != te && *q == '/')
		{
			++q;
			while (q != te && *q >= '0' && *q <= '9') { count = count * 10u + static_cast<unsigned>(*q - '0'); ++q; }
			if (count > 0 && count <= 255u) m.portCount = static_cast<uint8_t>(count);
		}
	}

	if (token(ts, te)) m.proto = spanOf(bodyBegin, ts, te);

	while (token(ts, te))
	{
		if (m.nFmt >= Limits::kMaxFormats)
		{
			// checkSdp() already refused a body with more <fmt> tokens than this on
			// the wire path, so reaching here means a locally built or test body.
			// Stop recording rather than overflow; the m= line span is kept intact
			// so verbatim relay is unaffected.
			break;
		}
		unsigned v = 0;
		bool numeric = true;
		for (const char* q = ts; q != te; ++q)
		{
			if (*q < '0' || *q > '9') { numeric = false; break; }
			v = v * 10u + static_cast<unsigned>(*q - '0');
		}
		if (!numeric || v > 127u)
		{
			// Preserved for relay, not answerable: choosing a payload type out of a
			// list we could not read would be a guess.
			m.malformedFmt = true;
			continue;
		}
		m.fmt[m.nFmt++] = static_cast<uint8_t>(v);
	}
}

// Append an attribute to a section, or report the cap as exceeded.
bool addAttr(Attribute* arr, uint8_t& n, unsigned cap,
	const char* bodyBegin, const char* b, const char* e)
{
	if (n >= cap) return false;   // caller turns this into a fail-closed verdict

	const char *nameEnd = nullptr, *valBegin = nullptr;
	splitAttr(b, e, nameEnd, valBegin);

	Attribute& a = arr[n];
	a.name  = spanOf(bodyBegin, b, nameEnd);
	a.value = (valBegin < e) ? spanOf(bodyBegin, valBegin, e) : Span{};

	// A name longer than the wire cap is not one we act on. checkSdp() already
	// refused it on the wire path; this is the guard for a locally routed body.
	if (static_cast<size_t>(nameEnd - b) > SdpLimits::kMaxAttrNameBytes)
	{
		a.kind = AttrKind::Other;
	}
	else
	{
		a.kind = lexAttrKind(b, nameEnd);
	}

	a.pt = 0xFF;
	if ((a.kind == AttrKind::Rtpmap || a.kind == AttrKind::Fmtp) && valBegin < e)
	{
		a.pt = lexLeadingPt(valBegin, e);
	}

	++n;
	return true;
}

}   // anonymous namespace

Verdict parse(std::string_view body, Session& out)
{
	// Reset first, unconditionally. A field present in a PREVIOUS body must never
	// survive into this one — the recycled pool-slot case, which is what makes a
	// stale model dangerous rather than merely wrong.
	out = Session{};

	const char* const begin = body.data();
	const char* const end   = begin + body.size();
	const char*       p     = begin;

	// -1 means "no m= seen yet", i.e. session level. RFC 8866 §5.7/§5.13: a c= or
	// a= line before the first m= is session-scoped; after one it belongs to that
	// section.
	int current = -1;

	unsigned lineNo = 0;
	while (p != end)
	{
		if (lineNo >= SdpLimits::kMaxLines)
		{
			return Verdict::TooManyLines;
		}
		++lineNo;

		// Cut one line. Primary delimiter "\r\n", bare "\n" tolerated — matching
		// the line splitting the previous parser used, so behaviour on
		// mixed/malformed line endings does not change.
		const char* lineEnd = static_cast<const char*>(std::memchr(p, '\n', static_cast<size_t>(end - p)));
		const char* next    = (lineEnd == nullptr) ? end : lineEnd + 1;
		const char* stop    = (lineEnd == nullptr) ? end : lineEnd;
		if (stop != p && stop[-1] == '\r') --stop;

		if (static_cast<size_t>(stop - p) > SdpLimits::kMaxLineBytes)
		{
			return Verdict::LineTooLong;
		}

		const LineTag tag = lexLineType(p, stop);
		const char* const val = (stop - p >= 2) ? p + 2 : stop;

		switch (tag)
		{
		// WHOLE LINE, prefix included -- see the span convention note in Sdp.hpp.
		case LineTag::V: out.version = spanOf(begin, p, stop); break;
		case LineTag::O: out.origin  = spanOf(begin, p, stop); break;
		case LineTag::S: out.name    = spanOf(begin, p, stop); break;
		case LineTag::T: out.time    = spanOf(begin, p, stop); break;

		case LineTag::C:
			// Media-level c= overrides the session's for that section only; this is
			// issue #196 item 2, the phones that emit c= ONLY per media.
			if (current >= 0) out.media[current].connection = spanOf(begin, p, stop);
			else              out.connection                = spanOf(begin, p, stop);
			break;

		case LineTag::B:
			if (current >= 0) out.media[current].bandwidth = spanOf(begin, p, stop);
			else              out.bandwidth                = spanOf(begin, p, stop);
			break;

		case LineTag::K:
			// Stored so relay stays faithful, never decoded. RFC 8866 §5.12
			// deprecates k= and nothing here interprets it.
			if (current >= 0) out.media[current].key = spanOf(begin, p, stop);
			else              out.key                = spanOf(begin, p, stop);
			break;

		case LineTag::M:
		{
			if (out.nMedia >= Limits::kMaxMediaSections)
			{
				return Verdict::TooManyMediaSections;   // fail closed → 488
			}
			current = out.nMedia++;
			Media& m = out.media[current];
			m = Media{};
			m.line = spanOf(begin, p, stop);   // whole line, for verbatim relay
			parseMediaLine(begin, val, stop, m);
			break;
		}

		case LineTag::A:
		{
			const bool ok = (current >= 0)
				? addAttr(out.media[current].attrs, out.media[current].nAttrs,
					Limits::kMaxAttributesPerSection, begin, val, stop)
				: addAttr(out.attrs, out.nAttrs,
					Limits::kMaxSessionAttributes, begin, val, stop);
			if (!ok) return Verdict::TooManyAttributes;   // fail closed → 488
			break;
		}

		case LineTag::Ignored:
		case LineTag::Empty:
			break;

		case LineTag::Unknown:
			if (out.unknownLines < 255) ++out.unknownLines;
			break;
		}

		p = next;
	}

	out.lines = static_cast<uint16_t>(lineNo);
	return Verdict::Ok;
}

}   // namespace sdp
