#include "Sdp.hpp"

// Hand-written half of the SDP model (issue #196).
//
// Deliberately NOT in Sdp.cpp. That file is generated from Sdp.re by re2c and
// is committed verbatim so CI can regenerate it and diff; mixing hand-written
// code into it would make the drift check impossible to read and tempt someone
// to "fix" a spurious diff by editing generated output. Sdp.cpp holds parse()
// and nothing else.
//
// Everything here is a bounded scan over fixed-capacity arrays: no recursion,
// no allocation, and no loop whose trip count depends on anything but a
// compile-time cap. tests/tools/check_parser_callgraph.py asserts that for the
// whole `sdp::` namespace, this file included.

namespace sdp
{

std::string_view view(std::string_view body, Span s)
{
	// Clamp rather than trust. A span is only ever as good as the body it was
	// parsed from, and this model is carried by objects the message pool copies
	// (`*msg = source`) -- the generation check in SipSdpMessage is what SHOULD
	// force a re-parse first, but if it ever fails to, the consequence must be an
	// in-bounds view of the wrong body rather than a read past the end of this
	// one. Cheap insurance against the only class of bug in this design that
	// would be a memory-safety issue rather than a wrong answer.
	if (s.len == 0) return std::string_view();
	if (s.pos >= body.size()) return std::string_view();

	const size_t avail = body.size() - s.pos;
	const size_t len   = (s.len < avail) ? static_cast<size_t>(s.len) : avail;
	return body.substr(s.pos, len);
}

Span effectiveConnection(const Session& s, unsigned mediaIndex)
{
	// RFC 8866 s5.7: a c= line before the first m= is session level; one inside a
	// media section belongs to that section and OVERRIDES the session's.
	//
	// This is issue #196 item 2. Some phones emit c= only per media and none at
	// session level, and the previous six-span cache looked at the session level
	// alone -- so getConnectionInformation() returned empty and the anchoring
	// path had no address to aim RTP at. Reimplementing the legacy accessor on
	// top of this function is what quietly fixes that for existing callers.
	if (mediaIndex < s.nMedia && !s.media[mediaIndex].connection.absent())
	{
		return s.media[mediaIndex].connection;
	}
	return s.connection;
}

namespace
{
	// The last direction-kind attribute in a list wins. Bounded by the caller's
	// count, which is itself bounded by a compile-time cap.
	//
	// "Last wins" rather than "first": a body carrying two direction attributes
	// is malformed, but every SDP stack in the field resolves it by later-wins
	// (it falls out of the natural "assign as you scan" implementation), so
	// matching that is the interoperable choice.
	bool lastDirectionIn(const Attribute* attrs, unsigned count, Direction& out)
	{
		bool found = false;
		for (unsigned i = 0; i < count; ++i)
		{
			switch (attrs[i].kind)
			{
			case AttrKind::Sendrecv: out = Direction::Sendrecv; found = true; break;
			case AttrKind::Sendonly: out = Direction::Sendonly; found = true; break;
			case AttrKind::Recvonly: out = Direction::Recvonly; found = true; break;
			case AttrKind::Inactive: out = Direction::Inactive; found = true; break;
			default: break;
			}
		}
		return found;
	}

	// Token `n` (0-based) of a space-separated line, without allocating.
	// Bounded by the line's own length, which checkSdp() has already capped.
	std::string_view nthToken(std::string_view line, unsigned n)
	{
		size_t i = 0;
		for (unsigned tok = 0;; ++tok)
		{
			while (i < line.size() && line[i] == ' ') ++i;
			if (i >= line.size()) return std::string_view();
			const size_t start = i;
			while (i < line.size() && line[i] != ' ') ++i;
			if (tok == n) return line.substr(start, i - start);
		}
	}
}

Direction effectiveDirection(const Session& s, unsigned mediaIndex)
{
	Direction d = Direction::Sendrecv;

	// Session level first, so a media-level attribute can override it.
	(void)lastDirectionIn(s.attrs, s.nAttrs, d);

	if (mediaIndex < s.nMedia)
	{
		Direction md;
		if (lastDirectionIn(s.media[mediaIndex].attrs, s.media[mediaIndex].nAttrs, md))
		{
			d = md;
		}
	}

	// RFC 8866 s6.7.4: absent from both levels means sendrecv, which is the
	// initial value above. Stated explicitly because "no attribute" meaning
	// "bidirectional" is the opposite of what a reader tends to assume.
	return d;
}

bool isHold(const Session& s, std::string_view body, unsigned mediaIndex)
{
	// Two signals, both live in the field, and a stack that checks only one gets
	// hold wrong against half the handsets it meets.
	//
	// 1. The modern one (RFC 3264 s8.4): direction is sendonly or inactive.
	const Direction d = effectiveDirection(s, mediaIndex);
	if (d == Direction::Sendonly || d == Direction::Inactive)
	{
		return true;
	}

	// 2. The legacy RFC 2543 one: the connection address is the unspecified
	//    address. Older phones signal hold by blackholing the media address
	//    rather than by changing direction.
	const std::string_view conn = view(body, effectiveConnection(s, mediaIndex));
	if (conn.empty()) return false;

	// "c=IN IP4 0.0.0.0" -- token 0 is "c=IN" as stored (the span covers the whole
	// line including its prefix), so the address is token 2.
	const std::string_view addr = nthToken(conn, 2);
	return addr == "0.0.0.0";
}

}   // namespace sdp
