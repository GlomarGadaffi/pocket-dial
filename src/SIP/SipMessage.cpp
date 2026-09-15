#include "SipMessage.hpp"
#include "Sdp.hpp"
#include <vector>
#include <cctype>
#include "SipMessageTypes.h"
#include <cstring>
#include <cctype>

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

	// Splits a raw SIP message into its start line, header lines (verbatim, in
	// order, duplicates preserved), and body. Tolerates bare-LF line endings and
	// a bare "\n\n" header/body separator — defensive parsing of untrusted
	// network input (SEC-02), mirroring the tolerance the old buffer-scanning
	// parse() had.
	void splitMessage(std::string_view raw, std::string& startLine,
		std::vector<std::string>& headerLines, std::string& body)
	{
		startLine.clear();
		headerLines.clear();
		body.clear();

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
			return;
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
			startLine = std::string(headerBlock);
			return;
		}

		startLine = std::string(headerBlock.substr(pos_start, pos_end - pos_start));
		pos_start = pos_end + lineDelimLen;

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
				headerLines.emplace_back(line);
			}
		}
	}
}

SipMessage::SipMessage(const std::string& message, sockaddr_in src) : _src(src)
{
	_hasSdp = mentionsSdpContentType(message);
	splitMessage(message, _startLine, _headerLines, _body);
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
	_headerLines = other._headerLines;
	_body        = other._body;
	_src         = other._src;
	++_bodyGen;
	return *this;
}

void SipMessage::reset(std::string_view message, sockaddr_in src)
{
	_src = src;
	_hasSdp = mentionsSdpContentType(message);
	// splitMessage() clear()s _headerLines rather than reassigning it, so a
	// pooled message's vector capacity survives across reset() calls.
	splitMessage(message, _startLine, _headerLines, _body);
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

void SipMessage::addHeader(const std::string& name, const std::string& value)
{
	insertHeaderLine(name + ": " + value);
}

void SipMessage::setHeaderOnce(const std::string& name, const std::string& value)
{
	setNamedHeader(name, {}, name + ": " + value);
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

	AudioPolicyResult applyAudioPolicy(std::string_view body, bool allowWideband)
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
			const bool keep = (pt == 0) || (pt == 8) || (allowWideband && pt == 9) || ev;
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

bool SipMessage::offersSupportedAudio(bool allowWideband) const
{
	const AudioPolicyResult r = applyAudioPolicy(_body, allowWideband);
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

bool SipMessage::filterAudioCodecs(bool allowWideband)
{
	const AudioPolicyResult r = applyAudioPolicy(_body, allowWideband);
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
	}
	return SdpVerdict::Ok;
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
	}
	return "rejected";
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
	std::string newLine = (fullForm ? "Content-Length: " : "l: ") + std::to_string(_body.size());
	_headerLines[idx] = std::move(newLine);
}

void SipMessage::clearBody()
{
	_body.clear();
	++_bodyGen;
	syncContentLength();
}

SipMessage::SdpDirection SipMessage::getSdpDirection() const
{
	// Issue #196: judged on the FIRST AUDIO stream through the sdp:: model, with
	// RFC 8866 scoping (a media-level direction overrides a session-level one)
	// and the RFC 2543 legacy hold form (c=0.0.0.0, no direction attribute at
	// all) reported as Inactive. `None` still means "no direction attribute
	// anywhere and no zero address", which is what the callers' Held/Connected
	// decision has always keyed on. Flat and bounded like every decoder here;
	// zero heap (SdpAdmission.DecodePathsAllocateNothing pins that).
	const std::string_view body(_body);
	sdp::Session& s = sdp::scratch(0);
	sdp::parse(body, s);

	auto map = [](sdp::Direction d) {
		switch (d)
		{
			case sdp::Direction::SendRecv: return SdpDirection::SendRecv;
			case sdp::Direction::SendOnly: return SdpDirection::SendOnly;
			case sdp::Direction::RecvOnly: return SdpDirection::RecvOnly;
			case sdp::Direction::Inactive: return SdpDirection::Inactive;
			default:                       return SdpDirection::None;
		}
	};

	int idx = s.firstAudio();
	if (idx < 0 && s.mediaCount > 0) idx = 0;
	if (idx < 0) return map(s.dir);   // no m= at all: session-level attribute or None

	const unsigned i = static_cast<unsigned>(idx);
	if (s.media[i].dir != sdp::Direction::None) return map(s.media[i].dir);
	if (s.dir != sdp::Direction::None) return map(s.dir);
	if (sdp::connectionAddress(body, sdp::effectiveConnection(s, i)).isZero) return SdpDirection::Inactive;
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
	out.reserve(_startLine.size() + 2 + _body.size() + 64);
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

bool SipMessage::isValidMessage() const
{
	// Structural validity (SEC-02): reject empty payloads and packets whose
	// start line / method-or-status token could not be parsed. A well-formed
	// SIP message always yields a non-empty start line and type token.
	if (_startLine.empty()) return false;
	if (getType().empty()) return false;
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
	size_t idx = findHeaderIndex("session-expires");
	if (idx == std::string::npos) return 0;
	std::string_view v = headerValueOf(_headerLines[idx]);
	uint32_t val = 0;
	size_t i = 0;
	while (i < v.size() && v[i] >= '0' && v[i] <= '9')
		val = val * 10 + static_cast<uint32_t>(v[i++] - '0');
	return val;
}

std::string_view SipMessage::getSessionExpiresRefresher() const
{
	size_t idx = findHeaderIndex("session-expires");
	if (idx == std::string::npos) return {};
	std::string_view line = _headerLines[idx];
	size_t rp = line.find("refresher=");
	if (rp == std::string_view::npos) return {};
	size_t vs = rp + 10;
	size_t ve = line.find_first_of("; \t\r\n", vs);
	if (ve == std::string_view::npos) ve = line.size();
	return line.substr(vs, ve - vs);
}

uint32_t SipMessage::getMinSESecs() const
{
	size_t idx = findHeaderIndex("min-se");
	if (idx == std::string::npos) return 0;
	std::string_view v = headerValueOf(_headerLines[idx]);
	uint32_t val = 0;
	size_t i = 0;
	while (i < v.size() && v[i] >= '0' && v[i] <= '9')
		val = val * 10 + static_cast<uint32_t>(v[i++] - '0');
	return val;
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

std::string_view SipMessage::getEvent() const
{
	size_t idx = findHeaderIndex("event", "o");
	return idx == std::string::npos ? std::string_view{} : std::string_view(_headerLines[idx]);
}

std::string_view SipMessage::extractNumber(std::string_view header) const
{
	auto sipPos = header.find("sip:");
	if (sipPos == std::string_view::npos)
		return {};

	auto start = sipPos + 4;
	auto atPos = header.find('@', start);
	if (atPos == std::string_view::npos)
		return {};

	return header.substr(start, atPos - start);
}
