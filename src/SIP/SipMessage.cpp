#include "SipMessage.hpp"
#include <cstdio>   // #463: syncContentLength formats into a stack buffer
#include <algorithm>
#include <vector>
#include <cctype>
#include "SipMessageTypes.h"
#include "EmergencyCall.hpp"   // #199: urn:service:sos, isEmergencyRequest(); #760: tel:911, urn:service:test.sos
#include "SipHeaderUtil.hpp"   // #835: siphdr::nameAddrOpen(), shared with contactUriView()
#include <cstring>
#include <cctype>
#include <cstdint>

namespace
{
	// Case-insensitive search for the SDP MIME type. MIME types are
	// case-insensitive (RFC 2045 §5.1), and a body whose Content-Type reads
	// "Application/SDP" is still SDP to the phone we would relay it to -- so it
	// must be SDP to the admission gate as well (SipMessage::checkSdp), or the
	// gate could be sidestepped by changing case. Flat scan, bounded by the
	// datagram size, no allocation.
	bool mentionsSdpContentType(std::string_view message)
	{
		static constexpr std::string_view kType = "application/sdp";
		if (message.size() < kType.size()) return false;
		for (size_t i = 0; i + kType.size() <= message.size(); ++i)
		{
			size_t k = 0;
			while (k < kType.size() &&
				std::tolower(static_cast<unsigned char>(message[i + k])) == kType[k]) ++k;
			if (k == kType.size()) return true;
		}
		return false;
	}

	bool iequal(std::string_view a, std::string_view b)
	{
		if (a.size() != b.size()) return false;
		for (size_t i = 0; i < a.size(); ++i)
			if (std::tolower(static_cast<unsigned char>(a[i])) !=
				std::tolower(static_cast<unsigned char>(b[i]))) return false;
		return true;
	}

	// First case-insensitive occurrence of an ASCII-lowercase needle, or npos.
	size_t ifindLower(std::string_view hay, std::string_view lowerNeedle)
	{
		if (lowerNeedle.empty() || hay.size() < lowerNeedle.size()) return std::string_view::npos;
		for (size_t i = 0; i + lowerNeedle.size() <= hay.size(); ++i)
		{
			size_t k = 0;
			while (k < lowerNeedle.size() &&
				std::tolower(static_cast<unsigned char>(hay[i + k])) == lowerNeedle[k]) ++k;
			if (k == lowerNeedle.size()) return i;
		}
		return std::string_view::npos;
	}

	// delta-seconds (RFC 4028 §3: Session-Expires, Min-SE), SATURATING at
	// UINT32_MAX. A plain uint32_t accumulator wraps, so "4294967296" read as 0
	// -- "no timer" -- and "4294967326" read as 30, which the 422 floor then
	// answered as if the phone had asked for 30 s (#739).
	uint32_t deltaSecondsOf(std::string_view v)
	{
		uint64_t val = 0;
		for (size_t i = 0; i < v.size() && v[i] >= '0' && v[i] <= '9'; ++i)
		{
			val = val * 10 + static_cast<uint64_t>(v[i] - '0');
			if (val > UINT32_MAX) return UINT32_MAX;
		}
		return static_cast<uint32_t>(val);
	}

	// Header name = text before the first ':', with surrounding whitespace
	// trimmed (tolerates a leading space before a compact header name, e.g.
	// " v: SIP/2.0/UDP ...", and any padding around the colon).
	std::string_view headerNameOf(std::string_view line)
	{
		size_t colonPos = line.find(':');
		if (colonPos == std::string_view::npos) return {};
		size_t nameEnd = colonPos;
		while (nameEnd > 0 && std::isspace(static_cast<unsigned char>(line[nameEnd - 1]))) --nameEnd;
		size_t nameStart = 0;
		while (nameStart < nameEnd && std::isspace(static_cast<unsigned char>(line[nameStart]))) ++nameStart;
		return line.substr(nameStart, nameEnd - nameStart);
	}

	// Header value = text after the first ':', with leading whitespace trimmed.
	std::string_view headerValueOf(std::string_view line)
	{
		size_t colon = line.find(':');
		if (colon == std::string_view::npos) return {};
		std::string_view v = line.substr(colon + 1);
		while (!v.empty() && std::isspace(static_cast<unsigned char>(v.front()))) v.remove_prefix(1);
		return v;
	}

	// #462 (#284 rank 1): keep every header-line BUFFER alive across parses.
	//
	// `lines` must end up holding exactly the parsed lines. The old way --
	// clear() then emplace_back() -- destroyed each std::string (freeing its
	// buffer) and allocated a fresh one per line on the next parse: roughly one
	// allocation per header line, on every packet, since almost every SIP header
	// line is longer than libstdc++'s 15-byte small-string buffer.
	//
	// Instead lines are ASSIGNED into strings that already have capacity, and
	// the ones a shorter message does not need are PARKED in `spare` rather than
	// destroyed, so the next longer message takes them back. Reuse in place
	// alone would not be enough: real traffic alternates shapes on the same
	// pooled slot (REGISTER, a 200, OPTIONS...), and shrinking the vector would
	// free exactly the buffers the next longer message then reallocates. Moving
	// a std::string moves its buffer, so parking and un-parking never allocate.
	std::string& nextLine(std::vector<std::string>& lines, std::vector<std::string>& spare,
		size_t& n)
	{
		if (n == lines.size())
		{
			if (!spare.empty())
			{
				lines.push_back(std::move(spare.back()));
				spare.pop_back();
			}
			else
			{
				lines.emplace_back();   // warm-up only: a buffer nobody has had yet
			}
		}
		return lines[n++];
	}

	// Park everything past the first `n` lines, buffers intact, up to
	// SipLimits::kMaxHeaderLines of them (#838); a line past that is freed.
	void parkSurplus(std::vector<std::string>& lines, std::vector<std::string>& spare, size_t n)
	{
		while (lines.size() > n)
		{
			if (spare.size() < SipLimits::kMaxHeaderLines) spare.push_back(std::move(lines.back()));
			lines.pop_back();
		}
	}

	size_t heapBytesOf(const std::string& s, size_t inlineCapacity)
	{
		return s.capacity() > inlineCapacity ? s.capacity() : 0;
	}

	// #838: lines are reused in place by position, so a long line at a
	// different position in each datagram would leave every position holding a
	// large buffer. Past SipLimits::kMaxKeptLineBytes, parked buffers are freed
	// first (no allocation), then a line holding more than it needs is given an
	// exact-size buffer. Legitimate traffic stays under the budget, so only a
	// run of oversized lines ever pays for an allocation here.
	void capKeptLineBytes(std::vector<std::string>& lines, std::vector<std::string>& spare)
	{
		const size_t inlineCapacity = std::string().capacity();
		size_t kept = 0;
		for (const std::string& s : lines) kept += heapBytesOf(s, inlineCapacity);
		for (const std::string& s : spare) kept += heapBytesOf(s, inlineCapacity);
		for (std::string& s : spare)
		{
			if (kept <= SipLimits::kMaxKeptLineBytes) return;
			kept -= heapBytesOf(s, inlineCapacity);
			std::string().swap(s);
		}
		for (std::string& s : lines)
		{
			if (kept <= SipLimits::kMaxKeptLineBytes) return;
			const size_t before = heapBytesOf(s, inlineCapacity);
			if (before == 0 || s.capacity() == s.size()) continue;
			std::string(s).swap(s);
			kept = kept - before + heapBytesOf(s, inlineCapacity);
		}
	}

	// Splits a raw SIP message into its start line, header lines (verbatim, in
	// order, duplicates preserved), and body. Tolerates bare-LF line endings and
	// a bare "\n\n" header/body separator — defensive parsing of untrusted
	// network input (SEC-02), mirroring the tolerance the old buffer-scanning
	// parse() had.
	//
	// Every output is written with assign() into storage that survives the call
	// (see nextLine()/parkSurplus() above), so parsing into a warmed pooled
	// message allocates nothing.
	//
	// #838: keeps at most `maxLines` header lines and returns true when there
	// were more. Storing every line of a datagram and counting afterwards let
	// one 2 KB datagram of short lines leave ~1000 line buffers in a pooled
	// message for good, refused or not.
	bool splitMessage(std::string_view raw, std::string& startLine,
		std::vector<std::string>& headerLines, std::vector<std::string>& spare,
		std::string& body, size_t maxLines)
	{
		startLine.clear();
		body.clear();
		size_t n = 0;   // header lines filled so far; everything past it is parked on exit

		size_t bodyStart = raw.find("\r\n\r\n");
		size_t sepLen = 4;
		if (bodyStart == std::string::npos)
		{
			bodyStart = raw.find("\n\n");
			sepLen = 2;
		}

		std::string_view headerBlock;
		if (bodyStart != std::string::npos)
		{
			headerBlock = std::string_view(raw.data(), bodyStart);
			// Issue #81: raw is now a view (into UdpServer::receiveLoop()'s stack
			// buffer on the wire path), so this substr() is itself a view — assign()
			// is what actually copies the bytes into the owned `body` string.
			body.assign(raw.substr(bodyStart + sepLen));
		}
		else
		{
			headerBlock = raw;
		}

		if (headerBlock.empty())
		{
			parkSurplus(headerLines, spare, 0);
			return false;
		}

		size_t pos_start = 0;
		size_t pos_end = headerBlock.find("\r\n");
		size_t lineDelimLen = 2;
		if (pos_end == std::string::npos)
		{
			pos_end = headerBlock.find("\n");
			lineDelimLen = 1;
		}

		if (pos_end == std::string::npos)
		{
			startLine.assign(headerBlock);
			parkSurplus(headerLines, spare, 0);
			return false;
		}

		// assign(), not `= std::string(...)`: the temporary always allocated.
		startLine.assign(headerBlock.substr(pos_start, pos_end - pos_start));
		pos_start = pos_end + lineDelimLen;

		bool tooMany = false;
		while (pos_start < headerBlock.size())
		{
			pos_end = headerBlock.find("\r\n", pos_start);
			size_t next_start = pos_end + 2;
			if (pos_end == std::string::npos)
			{
				pos_end = headerBlock.find("\n", pos_start);
				next_start = pos_end + 1;
			}

			std::string_view line;
			if (pos_end == std::string::npos)
			{
				line = headerBlock.substr(pos_start);
				pos_start = headerBlock.size();
			}
			else
			{
				line = headerBlock.substr(pos_start, pos_end - pos_start);
				pos_start = next_start;
			}

			if (!line.empty())
			{
				if (n == maxLines)
				{
					tooMany = true;
					break;
				}
				nextLine(headerLines, spare, n).assign(line);
			}
		}
		parkSurplus(headerLines, spare, n);
		capKeptLineBytes(headerLines, spare);
		return tooMany;
	}

	// A message the PBX built keeps every line (#838).
	constexpr size_t kEveryLine = static_cast<size_t>(-1);
}

SipMessage::SipMessage(const std::string& message, sockaddr_in src) : _src(src)
{
	_hasSdp = mentionsSdpContentType(message);
	_headerLinesTruncated = splitMessage(message, _startLine, _headerLines, _spareHeaderLines, _body, kEveryLine);
}

// Member-wise copy of everything EXCEPT _bodyGen, which advances instead — see
// the comment on _bodyGen. Keep this in sync if a member is ever added; the
// alternative (`= default`) silently reintroduces the stale-cache bug the
// generation counter exists to prevent.
// cppcheck flags _bodyGen as unassigned in operator=; the bump above IS the
// correct semantics, so the check is suppressed rather than satisfied.
// cppcheck-suppress operatorEqVarError
SipMessage& SipMessage::operator=(const SipMessage& other)
{
	if (this == &other) return *this;   // no body change, so no generation bump

	_hasSdp      = other._hasSdp;
	_startLine   = other._startLine;
	// Element-wise through the same keep-the-buffers path as splitMessage(),
	// rather than vector copy-assignment, which destroys the surplus strings
	// of a longer previous message. The pool copies into its slots this way
	// (getMessageFromPool(const SipMessage&)), so this is a hot path too.
	size_t n = 0;
	for (const std::string& line : other._headerLines)
	{
		nextLine(_headerLines, _spareHeaderLines, n).assign(line);
	}
	parkSurplus(_headerLines, _spareHeaderLines, n);
	capKeptLineBytes(_headerLines, _spareHeaderLines);
	_headerLinesTruncated = other._headerLinesTruncated;
	_body        = other._body;
	_src         = other._src;
	++_bodyGen;
	return *this;
}

void SipMessage::reset(std::string_view message, sockaddr_in src)
{
	resetWithin(message, src, kEveryLine);
}

void SipMessage::resetFromWire(std::string_view message, sockaddr_in src)
{
	resetWithin(message, src, SipLimits::kMaxHeaderLines);
}

void SipMessage::resetWithin(std::string_view message, sockaddr_in src, size_t maxHeaderLines)
{
	_src = src;
	_hasSdp = mentionsSdpContentType(message);
	// splitMessage() clear()s _headerLines rather than reassigning it, so a
	// pooled message's vector capacity survives across reset() calls.
	_headerLinesTruncated = splitMessage(message, _startLine, _headerLines, _spareHeaderLines, _body,
		maxHeaderLines);
	++_bodyGen;   // this is the pool-recycle path — see bodyGeneration()
}

// NOTE (audit #68): setType() was removed. It was dead code (zero call sites,
// grep-confirmed across src/, main/, tests/, sketches/) and its body conflated a
// _header-relative offset with a replace() length — a latent foot-gun if a future
// caller ever reused it on a non-start-line header. Rather than leave a method that
// only happens to work for the start line, the dead helper was deleted. If a
// method-token rewrite is ever needed, use setHeader() to rewrite the full line.

void SipMessage::setHeader(std::string value)
{
	_startLine = std::move(value);
}

size_t SipMessage::findHeaderIndex(std::string_view fullName, std::string_view compactName) const
{
	for (size_t i = 0; i < _headerLines.size(); ++i)
	{
		std::string_view name = headerNameOf(_headerLines[i]);
		if (iequal(name, fullName)) return i;
		if (!compactName.empty() && iequal(name, compactName)) return i;
	}
	return std::string::npos;
}

void SipMessage::insertHeaderLine(std::string value)
{
	// A new line takes a parked buffer when there is one. Adopting `value`'s
	// instead, while every reset() parks the surplus line, grew a pooled message
	// by one string per inserted header each time it was reused: the per-call
	// heap leak (888 answers, REGISTER 200s). Total line buffers now stay at the
	// most this message has held at once.
	if (!_spareHeaderLines.empty())
	{
		_spareHeaderLines.back().assign(value);
		value.swap(_spareHeaderLines.back());
		_spareHeaderLines.pop_back();
	}
	size_t clIdx = findHeaderIndex("content-length", "l");
	if (clIdx != std::string::npos)
	{
		_headerLines.insert(_headerLines.begin() + static_cast<long>(clIdx), std::move(value));
	}
	else
	{
		_headerLines.push_back(std::move(value));
	}
}

void SipMessage::setNamedHeader(std::string_view fullName, std::string_view compactName, std::string value)
{
	size_t idx = findHeaderIndex(fullName, compactName);
	if (idx != std::string::npos)
	{
		_headerLines[idx] = std::move(value);
	}
	else
	{
		insertHeaderLine(std::move(value));
	}
}

void SipMessage::setVia(std::string value)      { setNamedHeader("via", "v", std::move(value)); }
void SipMessage::setFrom(std::string value)     { setNamedHeader("from", "f", std::move(value)); }
void SipMessage::setTo(std::string value)       { setNamedHeader("to", "t", std::move(value)); }
void SipMessage::setCallID(std::string value)   { setNamedHeader("call-id", "i", std::move(value)); }
void SipMessage::setCSeq(std::string value)     { setNamedHeader("cseq", {}, std::move(value)); }
void SipMessage::setContact(std::string value)  { setNamedHeader("contact", "m", std::move(value)); }

void SipMessage::setContentLength(std::string value)
{
	// Unlike the other named setters, this one only ever updates an EXISTING
	// Content-Length header — every message we build already has one (it's
	// cloned from the incoming request), so there has never been an insert path
	// here, and syncContentLength()'s "absent -> no-op" contract depends on that.
	size_t idx = findHeaderIndex("content-length", "l");
	if (idx != std::string::npos)
	{
		_headerLines[idx] = std::move(value);
	}
}

namespace
{
	// "<name>: <value>" into `line`, reusing whatever capacity it has (#463).
	void composeHeaderLine(std::string& line, std::string_view name, std::string_view value)
	{
		line.clear();
		line.reserve(name.size() + 2 + value.size());
		line.append(name.data(), name.size());
		line.append(": ", 2);
		line.append(value.data(), value.size());
	}
}

size_t SipMessage::removeHeaders(std::string_view name)
{
	size_t removed = 0;
	for (size_t idx = findHeaderIndex(name); idx != std::string::npos; idx = findHeaderIndex(name))
	{
		_headerLines.erase(_headerLines.begin() + static_cast<long>(idx));
		++removed;
	}
	return removed;
}

void SipMessage::addHeader(std::string_view name, std::string_view value)
{
	std::string line;
	composeHeaderLine(line, name, value);
	insertHeaderLine(std::move(line));
}

void SipMessage::setHeaderOnce(std::string_view name, std::string_view value)
{
	const size_t idx = findHeaderIndex(name, {});
	if (idx != std::string::npos)
	{
		composeHeaderLine(_headerLines[idx], name, value);   // in place: no new allocation
		return;
	}
	std::string line;
	composeHeaderLine(line, name, value);
	insertHeaderLine(std::move(line));
}

void SipMessage::enforceG711()
{
	size_t mPos = _body.find("m=audio ");
	if (mPos != std::string::npos)
	{
		size_t lineEnd = _body.find("\r\n", mPos);
		if (lineEnd == std::string::npos) lineEnd = _body.find("\n", mPos);
		if (lineEnd == std::string::npos) lineEnd = _body.size();

		std::string_view mLine = std::string_view(_body).substr(mPos, lineEnd - mPos);
		size_t rtpPos = mLine.find("RTP/AVP ");
		if (rtpPos != std::string_view::npos)
		{
			std::string newMLine = std::string(mLine.substr(0, rtpPos + 8)) + "0 8 101";
			_body.replace(mPos, mLine.length(), newMLine);
		}
	}
	// Rewriting the codec list changed the SDP body size; resync Content-Length
	// so the answer isn't dropped as malformed on UDP.
	++_bodyGen;   // unconditional: cheaper than tracking whether the m= line matched
	syncContentLength();
}

namespace
{
	// ── Shared SDP line walker ───────────────────────────────────────────────
	// Returns the line starting at `pos` with its terminator stripped ("\r\n"
	// or bare "\n") and advances `pos` past it. Every SDP consumer in this file
	// walks the body through this one flat loop: there is no per-line callback,
	// no function pointer on the parser's stack and nothing that could re-enter
	// a line handler from inside another (docs/THREAT_MODEL.md T-7).
	std::string_view nextSdpLine(std::string_view body, size_t& pos)
	{
		const size_t eol = body.find('\n', pos);
		const size_t end = (eol == std::string_view::npos) ? body.size() : eol;
		std::string_view line = body.substr(pos, end - pos);
		if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
		pos = (eol == std::string_view::npos) ? body.size() : eol + 1;
		return line;
	}

	// Decimal prefix of `s` as an RTP payload type; -1 if absent or > 127.
	// The 7-bit bound is what lets every per-PT fact below live in a fixed
	// 128-slot table instead of a map.
	int parseIntPrefix(std::string_view s)
	{
		int v = 0;
		bool any = false;
		for (char c : s)
		{
			if (c < '0' || c > '9') break;
			v = v * 10 + (c - '0');
			any = true;
			if (v > 127) return -1;
		}
		return any ? v : -1;
	}

	// Case-insensitive equality against an ASCII-lowercase literal.
	bool iequalLower(std::string_view s, std::string_view lowerLit)
	{
		if (s.size() != lowerLit.size()) return false;
		for (size_t i = 0; i < s.size(); ++i)
			if (std::tolower(static_cast<unsigned char>(s[i])) != lowerLit[i]) return false;
		return true;
	}

	// One flat pass over an SDP body applying the relay codec policy. Fills the
	// kept payload types (m=audio order preserved), the dropped set, and reports
	// whether a real audio codec -- not just telephone-event -- survives.
	//
	// Zero heap and zero indirect calls on this path, by construction: the only
	// thing the policy needs from an a=rtpmap line is "is this PT
	// telephone-event", which is one bit per 7-bit payload type, and the m=
	// format list is captured into a fixed array. checkSdp() has already capped
	// the format count on the wire path, so the cap here is reached only by a
	// locally built message; extra formats are ignored, never decoded.
	struct AudioPolicyResult
	{
		bool    hasMLine = false;
		bool    hasAudio = false;
		uint8_t keptCount = 0;
		uint8_t droppedCount = 0;
		uint8_t kept[SdpLimits::kMaxMediaFormats] = {};   // m=audio order preserved
		bool    dropped[128] = {};                          // membership by payload type
		size_t  mPos = 0, mLen = 0;    // span of the m=audio line (no terminator)
		size_t  mPrefixLen = 0;        // length of "m=audio <port> <proto>" within it
	};

	AudioPolicyResult applyAudioPolicy(std::string_view body, bool allowWideband, bool allowPcma)
	{
		AudioPolicyResult r;
		bool     isEvent[128] = {};   // a=rtpmap:<pt> telephone-event/...
		uint8_t  offered[SdpLimits::kMaxMediaFormats];
		unsigned offeredCount = 0;

		size_t pos = 0;
		while (pos < body.size())
		{
			const size_t lineStart = pos;
			const std::string_view line = nextSdpLine(body, pos);
			if (line.rfind("a=rtpmap:", 0) == 0)
			{
				std::string_view rest = line.substr(9);
				int pt = parseIntPrefix(rest);
				size_t sp = rest.find(' ');
				if (pt >= 0 && sp != std::string_view::npos)
				{
					std::string_view name = rest.substr(sp + 1);
					size_t slash = name.find('/');
					if (slash != std::string_view::npos) name = name.substr(0, slash);
					isEvent[pt] = iequalLower(name, "telephone-event");   // last one wins
				}
			}
			else if (!r.hasMLine && line.rfind("m=audio ", 0) == 0)
			{
				r.hasMLine = true;
				r.mPos = lineStart;
				r.mLen = line.size();
				// m=audio <port> <proto> <fmt> <fmt> ...
				size_t p1 = line.find(' ');
				size_t p2 = (p1 == std::string_view::npos) ? p1 : line.find(' ', p1 + 1);
				size_t p3 = (p2 == std::string_view::npos) ? p2 : line.find(' ', p2 + 1);
				if (p3 == std::string_view::npos) { r.mPrefixLen = line.size(); continue; }
				r.mPrefixLen = p3;
				std::string_view fmts = line.substr(p3 + 1);
				size_t i = 0;
				while (i < fmts.size() && offeredCount < SdpLimits::kMaxMediaFormats)
				{
					while (i < fmts.size() && fmts[i] == ' ') ++i;
					size_t s = i;
					while (i < fmts.size() && fmts[i] != ' ') ++i;
					if (i > s)
					{
						int pt = parseIntPrefix(fmts.substr(s, i - s));
						if (pt >= 0) offered[offeredCount++] = static_cast<uint8_t>(pt);
					}
				}
			}
		}

		for (unsigned k = 0; k < offeredCount; ++k)
		{
			const uint8_t pt = offered[k];
			const bool ev = isEvent[pt];
			const bool keep = (pt == 0) || (allowPcma && pt == 8) || (allowWideband && pt == 9) || ev;
			if (keep)
			{
				r.kept[r.keptCount++] = pt;
				if (!ev) r.hasAudio = true;
			}
			else
			{
				r.dropped[pt] = true;
				++r.droppedCount;
			}
		}
		return r;
	}

	// a=<name> must be an RFC 4566 token. The charset is kept tighter than the
	// RFC's full token set on purpose: every attribute a real phone sends is
	// alnum plus '-', '_', '.', '+', and a name outside that is noise we would
	// otherwise relay unread.
	bool isAttrNameChar(char c)
	{
		const unsigned char u = static_cast<unsigned char>(c);
		return std::isalnum(u) || c == '-' || c == '_' || c == '.' || c == '+';
	}

	// SDP capability-negotiation attributes this PBX does not implement and
	// therefore refuses rather than relays: RFC 5939 (acap/tcap/pcfg/acfg/creq),
	// its media-level extension RFC 6871 (rmcap/omcap/mfcap/mscap/lcfg/sescap)
	// and RFC 7104 (bcap/ccap/icap). Each one carries a mini-grammar of its own
	// that a receiver is expected to decode and dispatch on -- the exact class
	// of "attribute that is really a program" behind the T612 RCE. a=csup is
	// deliberately NOT here: it only advertises support and an offer carrying it
	// alone is still a plain RFC 3264 offer (RFC 5939 §3.3.2), so rejecting it
	// would refuse well-behaved phones for nothing.
	bool isCapNegAttribute(std::string_view name)
	{
		static constexpr std::string_view kCapNeg[] = {
			"acap", "tcap", "pcfg", "acfg", "creq",
			"rmcap", "omcap", "mfcap", "mscap", "lcfg", "sescap",
			"bcap", "ccap", "icap",
		};
		for (std::string_view k : kCapNeg)
			if (iequalLower(name, k)) return true;
		return false;
	}
}

bool SipMessage::offersSupportedAudio(bool allowWideband, bool allowPcma) const
{
	const AudioPolicyResult r = applyAudioPolicy(_body, allowWideband, allowPcma);
	return !r.hasMLine || r.hasAudio;
}

int SipMessage::getTelephoneEventPayloadType() const
{
	// Deliberately a separate scan rather than another field on AudioPolicyResult:
	// that struct is built on the hot relay path for every INVITE, while this is
	// needed only when the server is ANSWERING with its own SDP (440/555/888 and
	// the voicemail/IVR roadmap). Keeping it out keeps the common path unchanged.
	//
	// Flat and bounded, matching applyAudioPolicy()'s discipline -- see the
	// CWE-674 note in SipSdpMessage.hpp for why attribute handling in this
	// codebase must never recurse or dispatch on attacker-chosen structure.
	int found = -1;
	size_t pos = 0;
	while (pos < _body.size())
	{
		const std::string_view line = nextSdpLine(_body, pos);
		if (line.rfind("a=rtpmap:", 0) != 0) continue;

		std::string_view rest = line.substr(9);
		const int pt = parseIntPrefix(rest);
		if (pt < 0 || pt > 127) continue;

		const size_t sp = rest.find(' ');
		if (sp == std::string_view::npos) continue;

		std::string_view name = rest.substr(sp + 1);
		const size_t slash = name.find('/');
		if (slash != std::string_view::npos) name = name.substr(0, slash);

		// Case-insensitive: the encoding name is not case sensitive per RFC 4566
		// §6, and phones do ship "TELEPHONE-EVENT".
		if (iequalLower(name, "telephone-event")) found = pt;   // last one wins
	}
	return found;
}

bool SipMessage::filterAudioCodecs(bool allowWideband, bool allowPcma)
{
	const AudioPolicyResult r = applyAudioPolicy(_body, allowWideband, allowPcma);
	if (!r.hasMLine) return true;        // nothing to negotiate
	if (!r.hasAudio) return false;       // caller answers 488; body left as offered
	if (r.droppedCount == 0) return true; // already within policy: no rewrite, no churn

	// The rewrite is the one place this path allocates: a fresh body of at most
	// the old body's size. That is a bounded copy of bytes checkSdp() already
	// admitted, not a decode -- nothing here is proportional to attribute
	// structure the peer chose.
	std::string out;
	out.reserve(_body.size());
	const std::string_view body(_body);
	size_t pos = 0;
	while (pos < body.size())
	{
		const size_t lineStart = pos;
		const std::string_view line = nextSdpLine(body, pos);
		const std::string_view raw = body.substr(lineStart, pos - lineStart);   // WITH terminator

		if (lineStart == r.mPos)
		{
			out.append(line.substr(0, r.mPrefixLen));
			for (unsigned k = 0; k < r.keptCount; ++k)
			{
				out += ' ';
				out += std::to_string(static_cast<int>(r.kept[k]));   // <= 3 digits: SSO, no heap
			}
			out.append(raw.substr(line.size()));   // original terminator
			continue;
		}
		bool drop = false;
		if (line.rfind("a=rtpmap:", 0) == 0 || line.rfind("a=fmtp:", 0) == 0)
		{
			size_t colon = line.find(':');
			int pt = parseIntPrefix(line.substr(colon + 1));
			drop = (pt >= 0) && r.dropped[pt];
		}
		if (!drop) out.append(raw);
	}
	_body = std::move(out);
	++_bodyGen;
	syncContentLength();
	return true;
}

SipMessage::SdpVerdict SipMessage::checkSdp() const
{
	using namespace SdpLimits;
	const std::string_view body(_body);
	if (body.size() > kMaxBodyBytes) return SdpVerdict::BodyTooLarge;

	unsigned lines = 0;
	// #199: the model's caps. Recorded, not returned, until the walk ends, so
	// every body refused before keeps exactly the verdict it had.
	unsigned sections = 0, attrs = 0, activeAudio = 0;
	SdpVerdict modelVerdict = SdpVerdict::Ok;
	size_t pos = 0;
	while (pos < body.size())
	{
		const std::string_view line = nextSdpLine(body, pos);
		if (line.empty()) continue;   // tolerated, as every decoder here tolerates it
		if (++lines > kMaxLines) return SdpVerdict::TooManyLines;

		// RFC 4566 §5: every line is exactly <type>=<value> with a one-letter type.
		if (line.size() < 2 || line[1] != '=' ||
			!std::isalpha(static_cast<unsigned char>(line[0])))
		{
			return SdpVerdict::MalformedLine;
		}

		// Attribute policy before the length and token caps: the name is read
		// through at most kMaxAttrNameBytes + 1 bytes whatever the line's length,
		// so this is bounded work, and it is the verdict that matters for the
		// canonical attack body (`a=acap:1 acap:1 ...` -- 1.4 KB on one line),
		// which violates all three. Naming the real reason in the 488's Warning
		// beats "line too long" when someone reads the phone's SIP trace.
		if (line[0] == 'a')
		{
			std::string_view name = line.substr(2, kMaxAttrNameBytes + 1);
			const size_t colon = name.find(':');
			if (colon != std::string_view::npos) name = name.substr(0, colon);
			if (name.empty() || name.size() > kMaxAttrNameBytes) return SdpVerdict::BadAttributeName;
			for (char c : name)
				if (!isAttrNameChar(c)) return SdpVerdict::BadAttributeName;
			if (isCapNegAttribute(name)) return SdpVerdict::CapabilityNegotiation;
		}

		if (line.size() > kMaxLineBytes) return SdpVerdict::LineTooLong;

		// Token count: SP-separated runs. Counted, never decoded. This is the
		// "attribute depth" bound -- there is no re-dispatch on tokens anywhere
		// in this parser, so depth is 1 by construction and the token cap is what
		// keeps the per-line work of any downstream decoder fixed.
		unsigned tokens = 0;
		bool inToken = false;
		for (char c : line)
		{
			if (c == ' ') { inToken = false; continue; }
			if (!inToken)
			{
				inToken = true;
				if (++tokens > kMaxTokensPerLine) return SdpVerdict::TooManyTokens;
			}
		}
		// m=<media> <port> <proto> <fmt>...: everything past the third token is a format.
		if (line[0] == 'm' && tokens > 3 + kMaxMediaFormats) return SdpVerdict::TooManyMediaFormats;

		// #199: the same section / attribute caps sdp::parse() fails closed on,
		// so a body this gate admits is one the model can hold. Counted only.
		if (modelVerdict != SdpVerdict::Ok) continue;
		if (line[0] == 'm')
		{
			attrs = 0;
			if (++sections > kMaxMediaSections) modelVerdict = SdpVerdict::TooManyMediaSections;
			// m=audio <port>...: a port of 0 is a removed stream, not an active one.
			else if (line.rfind("m=audio ", 0) == 0)
			{
				size_t p = 8;
				while (p < line.size() && line[p] == '0') ++p;
				const bool zeroPort = p > 8 && (p == line.size() || line[p] == ' ' || line[p] == '/');
				if (!zeroPort && ++activeAudio > kMaxActiveAudioStreams) modelVerdict = SdpVerdict::TooManyAudioStreams;
			}
		}
		else if (line[0] == 'a' &&
			++attrs > (sections == 0 ? kMaxSessionAttributes : kMaxAttributesPerSection))
		{
			modelVerdict = SdpVerdict::TooManyAttributes;
		}
	}
	return modelVerdict;
}

const char* SipMessage::sdpVerdictText(SdpVerdict v)
{
	switch (v)
	{
		case SdpVerdict::Ok:                    return "ok";
		case SdpVerdict::BodyTooLarge:          return "body too large";
		case SdpVerdict::TooManyLines:          return "too many lines";
		case SdpVerdict::LineTooLong:           return "line too long";
		case SdpVerdict::MalformedLine:         return "malformed line";
		case SdpVerdict::TooManyTokens:         return "too many tokens on a line";
		case SdpVerdict::TooManyMediaFormats:   return "too many media formats";
		case SdpVerdict::BadAttributeName:      return "bad attribute name";
		case SdpVerdict::CapabilityNegotiation: return "capability negotiation (RFC 5939) not supported";
		case SdpVerdict::TooManyMediaSections:  return "too many media sections";
		case SdpVerdict::TooManyAttributes:     return "too many attributes";
		case SdpVerdict::TooManyAudioStreams:   return "more than one audio stream";
	}
	return "rejected";
}

namespace
{
	// Entries in one header value: 1 + commas outside "quoted" and <angle> parts.
	unsigned countEntries(std::string_view v)
	{
		unsigned n = 1;
		bool quoted = false;
		int angle = 0;
		for (char c : v)
		{
			if (c == '"') quoted = !quoted;
			else if (quoted) continue;
			else if (c == '<') ++angle;
			else if (c == '>') { if (angle > 0) --angle; }
			else if (c == ',' && angle == 0) ++n;
		}
		return n;
	}

	std::string_view trimWs(std::string_view s)
	{
		while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
		while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) s.remove_suffix(1);
		return s;
	}

	// {1,maxDigits} decimal digits, value <= maxValue, nothing else.
	bool boundedNumber(std::string_view s, size_t maxDigits, uint64_t maxValue)
	{
		if (s.empty() || s.size() > maxDigits) return false;
		uint64_t v = 0;
		for (char c : s)
		{
			if (c < '0' || c > '9') return false;
			v = v * 10 + static_cast<uint64_t>(c - '0');
		}
		return v <= maxValue;
	}

	// Option tags this PBX honours in Require (RFC 3261 §8.2.2.3). "timer":
	// RFC 4028 is honoured passively (pjsua sends Require: timer on every
	// INVITE). "replaces": RFC 3891, see kSupportedOptionTags in
	// RequestsHandler.cpp. Everything else -- 100rel (no PRACK), path, gruu,
	// outbound, sec-agree -- is a 420.
	// A Content-Type value naming SDP. Media type only: parameters after ';' do
	// not change what we parse.
	bool isSdpMediaType(std::string_view contentTypeValue)
	{
		return iequalLower(trimWs(contentTypeValue.substr(0, contentTypeValue.find(';'))), "application/sdp");
	}

	bool isKnownOptionTag(std::string_view tag)
	{
		return iequalLower(tag, "timer") || iequalLower(tag, "replaces");
	}
}

SipMessage::HeaderVerdict SipMessage::checkHeaders(std::string_view& unsupported) const
{
	using namespace SipLimits;
	unsupported = {};
	const bool isRequest = !getStatusInfo().has_value();
	const std::string_view method = getType();

	// Buffer bounds: every message, since responses reach the same slots.
	if (getCallID().size() > kMaxCallIdLine) return HeaderVerdict::CallIdTooLong;
	if (getViaBranch().size() > kMaxBranch) return HeaderVerdict::BranchTooLong;
	{
		// CSeq: 1*10DIGIT LWS Method (RFC 3261 §20.16), number < 2^31.
		const std::string_view v = trimWs(headerValueOf(getCSeq()));
		const size_t sp = v.find_first_of(" \t");
		if (sp == std::string_view::npos) return HeaderVerdict::BadCSeq;
		const std::string_view m = trimWs(v.substr(sp));
		if (!boundedNumber(v.substr(0, sp), kMaxCSeqDigits, 0x7FFFFFFFu) ||
			m.empty() || m.size() > kMaxCSeqMethod || m.find_first_of(" \t") != std::string_view::npos)
		{
			return HeaderVerdict::BadCSeq;
		}
	}
	if (!isRequest) return HeaderVerdict::Ok;

	if (_headerLinesTruncated || _headerLines.size() > kMaxHeaderLines) return HeaderVerdict::TooManyHeaders;

	const bool checkRequire = method != SipMessageTypes::ACK && method != SipMessageTypes::CANCEL;
	const bool checkBody = !_body.empty() &&
		(method == SipMessageTypes::INVITE || method == SipMessageTypes::UPDATE);
	unsigned via = 0, route = 0, recordRoute = 0, contact = 0;
	bool sdpBody = false;
	for (const std::string& line : _headerLines)
	{
		const std::string_view name = headerNameOf(line);
		const std::string_view value = headerValueOf(line);
		if (iequal(name, "via") || iequal(name, "v"))
		{
			via += countEntries(value);
			if (via > kMaxVia) return HeaderVerdict::TooManyVia;
		}
		else if (iequal(name, "route"))
		{
			route += countEntries(value);
			if (route > kMaxRoute) return HeaderVerdict::TooManyRoute;
		}
		else if (iequal(name, "record-route"))
		{
			recordRoute += countEntries(value);
			if (recordRoute > kMaxRecordRoute) return HeaderVerdict::TooManyRecordRoute;
		}
		else if (iequal(name, "contact") || iequal(name, "m"))
		{
			contact += countEntries(value);
			if (contact > kMaxContact) return HeaderVerdict::TooManyContact;
		}
		else if (iequal(name, "max-forwards"))
		{
			if (!boundedNumber(trimWs(value), 3, kMaxMaxForwards)) return HeaderVerdict::BadMaxForwards;
		}
		else if (checkRequire && (iequal(name, "require") || iequal(name, "proxy-require")))
		{
			std::string_view rest = value;
			while (!rest.empty())
			{
				const size_t comma = rest.find(',');
				const std::string_view tag = trimWs(rest.substr(0, comma));
				rest = (comma == std::string_view::npos) ? std::string_view{} : rest.substr(comma + 1);
				if (!tag.empty() && !isKnownOptionTag(tag))
				{
					unsupported = tag;
					return HeaderVerdict::UnsupportedOption;
				}
			}
		}
		else if (iequal(name, "content-type") || iequal(name, "c"))
		{
			sdpBody = isSdpMediaType(value);
		}
	}
	// RFC 3261 §21.4.13: a body we do not parse, or one with no Content-Type.
	if (checkBody && !sdpBody) return HeaderVerdict::UnsupportedMediaType;
	return HeaderVerdict::Ok;
}

bool SipMessage::hasSdpContentType() const
{
	for (const std::string& line : _headerLines)
	{
		const std::string_view name = headerNameOf(line);
		if ((iequal(name, "content-type") || iequal(name, "c")) && isSdpMediaType(headerValueOf(line))) return true;
	}
	return false;
}

void SipMessage::setSdpContentType()
{
	size_t first = std::string::npos;
	for (size_t i = 0; i < _headerLines.size();)
	{
		const std::string_view name = headerNameOf(_headerLines[i]);
		if (!iequal(name, "content-type") && !iequal(name, "c"))
		{
			++i;
		}
		else if (first == std::string::npos)
		{
			first = i++;
		}
		else
		{
			if (_spareHeaderLines.size() < SipLimits::kMaxHeaderLines) _spareHeaderLines.push_back(std::move(_headerLines[i]));
			_headerLines.erase(_headerLines.begin() + static_cast<long>(i));
		}
	}
	if (first == std::string::npos)
	{
		addHeader("Content-Type", "application/sdp");
	}
	else if (!isSdpMediaType(headerValueOf(_headerLines[first])))
	{
		composeHeaderLine(_headerLines[first], "Content-Type", "application/sdp");
	}
}

const char* SipMessage::headerVerdictText(HeaderVerdict v)
{
	switch (v)
	{
		case HeaderVerdict::Ok:                   return "ok";
		case HeaderVerdict::TooManyHeaders:       return "too many header lines";
		case HeaderVerdict::CallIdTooLong:        return "Call-ID too long";
		case HeaderVerdict::BranchTooLong:        return "Via branch too long";
		case HeaderVerdict::BadCSeq:              return "malformed CSeq";
		case HeaderVerdict::BadMaxForwards:       return "malformed Max-Forwards";
		case HeaderVerdict::TooManyVia:           return "too many Via entries";
		case HeaderVerdict::TooManyRoute:         return "too many Route entries";
		case HeaderVerdict::TooManyRecordRoute:   return "too many Record-Route entries";
		case HeaderVerdict::TooManyContact:       return "too many Contact entries";
		case HeaderVerdict::UnsupportedOption:    return "unsupported option tag";
		case HeaderVerdict::UnsupportedMediaType: return "unsupported body type";
	}
	return "rejected";
}

bool SipMessage::isPsapCallback() const
{
	for (const std::string& line : _headerLines)
	{
		if (iequal(headerNameOf(line), "priority") &&
			iequalLower(trimWs(headerValueOf(line)), "psap-callback"))
		{
			return true;
		}
	}
	return false;
}

bool SipMessage::isEmergencyRequest() const
{
	if (getStatusInfo().has_value()) return false;
	if (getType() != SipMessageTypes::INVITE) return false;
	// #824: by the To user alone, the number onInvite routes on. A 911
	// Request-URI over To 102 is a call to 102 and gets no emergency yield.
	return pbx::classifyEmergencyDial(getToNumber()).isEmergency || isPsapCallback();
}

void SipMessage::syncContentLength()
{
	size_t idx = findHeaderIndex("content-length", "l");
	if (idx == std::string::npos)
	{
		return; // no Content-Length header present to update
	}

	// Preserve whichever header-name form the message already uses.
	bool fullForm = _headerLines[idx].find("Content-Length") != std::string::npos;
	// #463: rewritten in place from a stack buffer. The old "Content-Length: " +
	// to_string() built a 17+ char temporary (past SSO) on every clearBody() /
	// setBody() -- i.e. on most responses this PBX builds.
	char digits[24];
	const int n = std::snprintf(digits, sizeof(digits), "%zu", _body.size());
	std::string& line = _headerLines[idx];
	line.assign(fullForm ? "Content-Length: " : "l: ");
	if (n > 0) line.append(digits, static_cast<size_t>(n));
}

void SipMessage::clearBody()
{
	_body.clear();
	++_bodyGen;
	syncContentLength();
}

SipMessage::SdpDirection SipMessage::getSdpDirection() const
{
	const std::string_view whole(_body);
	size_t pos = 0;
	while (pos < whole.size())
	{
		const std::string_view line = nextSdpLine(whole, pos);
		if (line == "a=sendrecv") return SdpDirection::SendRecv;
		if (line == "a=sendonly") return SdpDirection::SendOnly;
		if (line == "a=recvonly") return SdpDirection::RecvOnly;
		if (line == "a=inactive") return SdpDirection::Inactive;
	}
	return SdpDirection::None;
}

std::string_view SipMessage::getBody() const
{
	return _body;
}

void SipMessage::setBody(const std::string& body)
{
	_body = body;
	++_bodyGen;
	syncContentLength();   // keep Content-Length honest (the 777-bug class)
}

bool SipMessage::unwrapMultipartSdp()
{
	const size_t ctIdx = findHeaderIndex("content-type", "c");
	if (ctIdx == std::string::npos) return false;
	const std::string_view ct = headerValueOf(_headerLines[ctIdx]);
	if (ifindLower(ct, "multipart/") != 0) return false;
	// RFC 2046 §5.1.1: boundary=<token> or boundary="<quoted>", 1 to 70 bytes.
	const size_t bpos = ifindLower(ct, "boundary=");
	if (bpos == std::string_view::npos) return false;
	std::string_view boundary = ct.substr(bpos + 9);
	if (!boundary.empty() && boundary.front() == '"')
	{
		boundary.remove_prefix(1);
		boundary = boundary.substr(0, boundary.find('"'));
	}
	else
	{
		boundary = boundary.substr(0, boundary.find_first_of("; \t\r"));
	}
	if (boundary.empty() || boundary.size() > 70) return false;

	// One flat walk, the same loop checkSdp() uses. A delimiter line is "--"
	// + boundary (the closing one adds "--"). A part's header lines run to its
	// first empty line; its body then runs to the CRLF before the next
	// delimiter, which RFC 2046 §5.1.1 gives to the delimiter, not the part.
	const std::string_view body(_body);
	size_t pos = 0;
	bool inHeaders = false;
	bool sdpPart = false;
	size_t sdpStart = std::string_view::npos;
	size_t sdpEnd = std::string_view::npos;
	while (pos < body.size())
	{
		const size_t lineStart = pos;
		const std::string_view line = nextSdpLine(body, pos);
		if (line.size() >= boundary.size() + 2 && line[0] == '-' && line[1] == '-' &&
			line.substr(2, boundary.size()) == boundary)
		{
			if (sdpStart != std::string_view::npos)
			{
				sdpEnd = lineStart;
				if (sdpEnd > sdpStart && body[sdpEnd - 1] == '\n') --sdpEnd;
				if (sdpEnd > sdpStart && body[sdpEnd - 1] == '\r') --sdpEnd;
				break;
			}
			inHeaders = true;
			sdpPart = false;
			continue;
		}
		if (!inHeaders) continue;   // the preamble, or a part that is not kept
		if (line.empty())
		{
			inHeaders = false;
			if (sdpPart) sdpStart = pos;
			continue;
		}
		if (iequal(headerNameOf(line), "content-type") &&
			ifindLower(headerValueOf(line), "application/sdp") == 0)
		{
			sdpPart = true;
		}
	}
	if (sdpStart == std::string_view::npos || sdpEnd == std::string_view::npos) return false;

	_body.erase(0, sdpStart);        // shifts in place: no new allocation
	_body.resize(sdpEnd - sdpStart);
	++_bodyGen;
	composeHeaderLine(_headerLines[ctIdx], "Content-Type", "application/sdp");
	syncContentLength();
	return true;
}

std::string SipMessage::toString() const
{
	std::string out;
	toString(out);
	return out;
}

// Issue #101(D): serialize into a caller-owned buffer so a caller that
// serializes the same message repeatedly — or one per packet on the hot path,
// like the /api/pcap capture — can reuse one allocation instead of paying for a
// fresh temporary every time. `out` is cleared first; clear() keeps its capacity,
// which is the whole point.
void SipMessage::toString(std::string& out) const
{
	out.clear();
	// Issue #316: the reserve must cover the header lines too, or std::string
	// reallocates partway through the loop below on essentially every call --
	// exactly the grow-copy-free churn this out-param form exists to avoid.
	// Exact rather than approximate: no fudge factor to keep in sync by hand.
	std::size_t need = _startLine.size() + 2 + _body.size() + 2;
	for (const auto& line : _headerLines) need += line.size() + 2;
	out.reserve(need);
	out += _startLine;
	out += "\r\n";
	for (const auto& line : _headerLines)
	{
		out += line;
		out += "\r\n";
	}
	out += "\r\n";
	out += _body;
}

std::size_t SipMessage::serializeInto(char* out, std::size_t cap) const
{
	std::size_t pos = 0;
	auto put = [&](const char* p, std::size_t n) {
		if (pos < cap) std::memcpy(out + pos, p, std::min(n, cap - pos));
		pos += n;
	};
	put(_startLine.data(), _startLine.size());
	put("\r\n", 2);
	for (const auto& line : _headerLines)
	{
		put(line.data(), line.size());
		put("\r\n", 2);
	}
	put("\r\n", 2);
	put(_body.data(), _body.size());
	return pos;
}

bool SipMessage::isValidMessage() const
{
	// Structural validity (SEC-02): reject empty payloads and packets whose
	// start line / method-or-status token could not be parsed. A well-formed
	// SIP message always yields a non-empty start line and type token.
	if (_startLine.empty()) return false;
	if (getType().empty()) return false;

	// Issue #265: SECURITY_AUDIT.md's SEC-02 entry has always described this
	// check as also verifying the five headers RFC 3261 s8.1.1/s8.2.6.2
	// requires on every request AND every response alike -- Via, To, From,
	// Call-ID, CSeq (Max-Forwards is request-only, so it is deliberately not
	// checked here). The code did not actually do that; this closes the gap
	// the doc always claimed was closed, rather than weakening the doc to
	// match a narrower check. A message missing any one of these cannot be
	// correlated to a dialog or transaction downstream regardless -- rejecting
	// it here, loudly and once, beats letting a handler further down discover
	// the same absence with no equivalent guard of its own.
	if (getVia().empty()) return false;
	if (getTo().empty()) return false;
	if (getFrom().empty()) return false;
	if (getCallID().empty()) return false;
	if (getCSeq().empty()) return false;
	return true;
}

std::string_view SipMessage::getType() const
{
	size_t sp = _startLine.find(' ');
	std::string_view first = (sp == std::string::npos)
		? std::string_view(_startLine)
		: std::string_view(_startLine).substr(0, sp);
	if (first == "SIP/2.0")
	{
		return _startLine;
	}
	return first;
}

std::string_view SipMessage::getHeader() const
{
	return _startLine;
}

std::string_view SipMessage::getVia() const
{
	size_t idx = findHeaderIndex("via", "v");
	return idx == std::string::npos ? std::string_view{} : std::string_view(_headerLines[idx]);
}

std::string_view SipMessage::getFrom() const
{
	size_t idx = findHeaderIndex("from", "f");
	return idx == std::string::npos ? std::string_view{} : std::string_view(_headerLines[idx]);
}

std::string_view SipMessage::getFromNumber() const
{
	return extractNumber(getFrom());
}

std::string_view SipMessage::getTo() const
{
	size_t idx = findHeaderIndex("to", "t");
	return idx == std::string::npos ? std::string_view{} : std::string_view(_headerLines[idx]);
}

std::string_view SipMessage::getToNumber() const
{
	return extractNumber(getTo());
}

std::string_view SipMessage::getCallID() const
{
	size_t idx = findHeaderIndex("call-id", "i");
	return idx == std::string::npos ? std::string_view{} : std::string_view(_headerLines[idx]);
}

std::string_view SipMessage::getCSeq() const
{
	size_t idx = findHeaderIndex("cseq");
	return idx == std::string::npos ? std::string_view{} : std::string_view(_headerLines[idx]);
}

std::string_view SipMessage::getViaBranch() const
{
	std::string_view via = getVia();
	auto pos = via.find("branch=");
	if (pos == std::string_view::npos) return {};
	pos += 7;
	auto end = via.find(';', pos);
	if (end == std::string_view::npos) end = via.size();
	return via.substr(pos, end - pos);
}

std::string_view SipMessage::getCSeqMethod() const
{
	std::string_view cSeq = getCSeq();
	auto sp = cSeq.rfind(' ');
	if (sp == std::string_view::npos) return {};
	auto method = cSeq.substr(sp + 1);
	while (!method.empty() && (method.back() == ' ' || method.back() == '\r' || method.back() == '\n'))
		method.remove_suffix(1);
	return method;
}

uint32_t SipMessage::getSessionExpiresSecs() const
{
	size_t idx = findHeaderIndex("session-expires", "x");
	if (idx == std::string::npos) return 0;
	return deltaSecondsOf(headerValueOf(_headerLines[idx]));
}

std::string_view SipMessage::getSessionExpiresRefresher() const
{
	size_t idx = findHeaderIndex("session-expires", "x");
	if (idx == std::string::npos) return {};
	std::string_view line = _headerLines[idx];
	// The parameter name and its uac/uas value are case-insensitive (RFC 3261
	// §7.3.1, RFC 4028 §4 ABNF): "Refresher=UAS" names the PBX's peer as
	// refresher just as "refresher=uas" does. The value is handed back as the
	// lowercase literal so every caller's `== "uas"` compare holds (#739).
	static constexpr std::string_view kParam = "refresher=";
	size_t rp = ifindLower(line, kParam);
	if (rp == std::string_view::npos) return {};
	size_t vs = rp + kParam.size();
	size_t ve = line.find_first_of("; \t\r\n", vs);
	if (ve == std::string_view::npos) ve = line.size();
	std::string_view value = line.substr(vs, ve - vs);
	if (iequal(value, "uac")) return "uac";
	if (iequal(value, "uas")) return "uas";
	return value;
}

uint32_t SipMessage::getMinSESecs() const
{
	size_t idx = findHeaderIndex("min-se");
	if (idx == std::string::npos) return 0;
	return deltaSecondsOf(headerValueOf(_headerLines[idx]));
}

std::string_view SipMessage::getContact() const
{
	size_t idx = findHeaderIndex("contact", "m");
	return idx == std::string::npos ? std::string_view{} : std::string_view(_headerLines[idx]);
}

std::string_view SipMessage::getContactNumber() const
{
	return extractNumber(getContact());
}

sockaddr_in SipMessage::getSource() const
{
	return _src;
}

std::string_view SipMessage::getContentLength() const
{
	size_t idx = findHeaderIndex("content-length", "l");
	return idx == std::string::npos ? std::string_view{} : std::string_view(_headerLines[idx]);
}

std::string_view SipMessage::getAuthorization() const
{
	size_t idx = findHeaderIndex("authorization");
	return idx == std::string::npos ? std::string_view{} : std::string_view(_headerLines[idx]);
}

std::string_view SipMessage::getHeaderLine(std::string_view name) const
{
	size_t idx = findHeaderIndex(name);
	return idx == std::string::npos ? std::string_view{} : std::string_view(_headerLines[idx]);
}

std::string_view SipMessage::getEvent() const
{
	size_t idx = findHeaderIndex("event", "o");
	return idx == std::string::npos ? std::string_view{} : std::string_view(_headerLines[idx]);
}

namespace
{
	// #760 review: the URI a To/From/Contact line or a request line carries,
	// and nothing around it. A name-addr's URI is inside <...>, the one
	// siphdr::nameAddrOpen() picks (#824, #832, #835: quoted display names and
	// parameters, and a quote left open). Without brackets it is the bare URI:
	// a request line's Request-URI, the token after the method, or a header's
	// value up to its first ';' (RFC 3261 s20.10). A quote left open with no
	// '<' gives empty.
	std::string_view uriPartOf(std::string_view line)
	{
		bool open = false;
		const size_t lt = siphdr::nameAddrOpen(line, open);
		if (lt != std::string_view::npos)
		{
			std::string_view uri = line.substr(lt + 1);
			uri = uri.substr(0, uri.find('>'));
			while (!uri.empty() && (uri.front() == ' ' || uri.front() == '\t')) uri.remove_prefix(1);
			while (!uri.empty() && (uri.back() == ' ' || uri.back() == '\t')) uri.remove_suffix(1);
			return uri;
		}
		if (open) return {};
		const size_t colon = line.find(':');
		if (colon == std::string_view::npos) return {};
		size_t nameStart = 0;
		size_t nameEnd = colon;
		while (nameStart < nameEnd && (line[nameStart] == ' ' || line[nameStart] == '\t')) ++nameStart;
		while (nameEnd > nameStart && (line[nameEnd - 1] == ' ' || line[nameEnd - 1] == '\t')) --nameEnd;
		// A header name holds no space, so "INVITE tel" before the first ':'
		// is a request line, and its URI begins after the method.
		const size_t sp = line.substr(nameStart, nameEnd - nameStart).find_first_of(" \t");
		std::string_view uri = line.substr(sp == std::string_view::npos ? colon + 1 : nameStart + sp);
		while (!uri.empty() && (uri.front() == ' ' || uri.front() == '\t')) uri.remove_prefix(1);
		return uri.substr(0, uri.find_first_of(" \t;\r\n"));
	}

	// #760: the two non-sip: forms a phone may legitimately dial for help. An
	// RFC 3966 tel:911 / tel:933 has no host and no '@', and RFC 5031's
	// urn:service:test.sos is the E911 test service (933 here). Only an
	// emergency number is mapped: every other tel: or urn: URI still reads as
	// no user, so nothing else changes. urn:service:sos itself is #199's.
	// #760 review: only the URI's own scheme is matched, never a display name
	// or a parameter ("Hotel:911 lobby" is not 911), and a tel: number counts
	// exactly when a sip: user would, so tel:9911 is 911 as sip:9911@ is.
	std::string_view emergencyUserOf(std::string_view header)
	{
		static constexpr std::string_view kTel = "tel:";
		static constexpr std::string_view kTestSos = "urn:service:test.sos";
		const std::string_view uri = uriPartOf(header);
		auto delimited = [&uri](size_t end) {
			return end == uri.size() || uri[end] == ';' || uri[end] == '?';
		};
		if (iequalLower(uri.substr(0, kTel.size()), kTel))
		{
			size_t end = kTel.size();
			while (end < uri.size() && std::isdigit(static_cast<unsigned char>(uri[end]))) ++end;
			const std::string_view digits = uri.substr(kTel.size(), end - kTel.size());
			if (delimited(end) && pbx::classifyEmergencyDial(digits).isEmergency) return digits;
		}
		if (iequalLower(uri.substr(0, kTestSos.size()), kTestSos))
		{
			// RFC 5031 s4.2: test.sos.<sub> is the same test service.
			const size_t end = kTestSos.size();
			if (delimited(end) || uri[end] == '.') return pbx::kEmergencyTestNumber;
		}
		return {};
	}
}

std::string_view SipMessage::extractNumber(std::string_view header) const
{
	// #824: only the URI is read, and its own scheme must start it. A display
	// name or a parameter never counts, either way: To: "sip:911@lobby"
	// <tel:+15551230100> is not a call to 911, and "sip:102@lobby" <sip:911@x>
	// is not a call to 102.
	const std::string_view uri = uriPartOf(header);
	// RFC 3261 s19.1.4: the scheme is case-insensitive, and a sips: URI (s19.1)
	// names its user the same way.
	const size_t scheme = iequalLower(uri.substr(0, 4), "sip:") ? 4
		: iequalLower(uri.substr(0, 5), "sips:") ? 5 : 0;
	if (scheme == 0)
	{
		// #199, RFC 5031 / 6881: urn:service:sos[.<sub>] IS an emergency call.
		// It has no sip: user part, so it used to read as empty and the INVITE
		// was answered 400. It is routed exactly as a dialed 911.
		static constexpr std::string_view kSos = "urn:service:sos";
		const size_t end = kSos.size();
		if (iequalLower(uri.substr(0, end), kSos) &&
			(end == uri.size() || uri[end] == '.' || uri[end] == ';'))
		{
			return pbx::kEmergencyNumber;
		}
		return emergencyUserOf(header);   // #760: tel:911 and urn:service:test.sos
	}

	const size_t atPos = uri.find('@', scheme);
	if (atPos == std::string_view::npos)
		return {};

	return uri.substr(scheme, atPos - scheme);
}
