#ifndef SIP_HEADER_UTIL_HPP
#define SIP_HEADER_UTIL_HPP

#include <cctype>
#include <cstdint>
#include <string>
#include <string_view>

namespace siphdr
{
	// Extract the ;tag= value from a From/To header line.
	inline std::string tagOf(std::string_view header)
	{
		size_t p = header.find(";tag=");
		if (p == std::string_view::npos) return {};
		p += 5;
		size_t e = p;
		while (e < header.size() && header[e] != ';' && header[e] != '>' &&
			header[e] != ' ' && header[e] != '\r' && header[e] != '\n')
		{
			++e;
		}
		return std::string(header.substr(p, e - p));
	}

	// Appends the ";tag=..." suffix found in `source` (if any) onto `header` in place.
	// Used when building a new From/To header that must carry over the dialog tag
	// from a different (already-tagged) header line.
	inline void appendTagFrom(std::string& header, std::string_view source)
	{
		size_t tagPos = source.find(";tag=");
		if (tagPos != std::string_view::npos)
		{
			header += source.substr(tagPos);
		}
	}

	// Strip a leading "HeaderName:" prefix (e.g. "From:", "To:", "Call-ID:") so
	// server-minted requests emit a clean value and never ship a doubled prefix.
	// Safe on bare values (the check is that the text before ':' contains only
	// letter/hyphen chars — so "<sip:...>" is left untouched). Idempotent.
	//
	// The view form (#464) is for comparisons, where the copy stripHeaderName()
	// makes is pure per-packet waste. It views into `h`, so it lives as long as h.
	inline std::string_view stripHeaderNameView(std::string_view h)
	{
		size_t colon = h.find(':');
		if (colon == std::string_view::npos || colon == 0 || colon > 15)
			return h;
		for (size_t i = 0; i < colon; ++i)
		{
			char c = h[i];
			if (!(std::isalpha(static_cast<unsigned char>(c)) || c == '-'))
				return h;
		}
		size_t v = colon + 1;
		while (v < h.size() && (h[v] == ' ' || h[v] == '\t')) ++v;
		size_t e = h.size();
		while (e > v && (h[e - 1] == '\r' || h[e - 1] == '\n')) --e;
		return h.substr(v, e - v);
	}

	inline std::string stripHeaderName(std::string_view h)
	{
		return std::string(stripHeaderNameView(h));
	}

	// Parse the leading digits out of a CSeq header line ("CSeq: 100 INVITE")
	// or an already-stripped value ("100 INVITE") -- either form works, since
	// this strips the header name itself first. Returns 0 on anything
	// unparseable; callers must treat 0 as "absent/unknown", never as a real
	// CSeq value (RFC 3261 places no floor on where a UA's own counter starts,
	// but a well-formed request always has SOME digits here).
	inline uint32_t cseqNumber(std::string_view header)
	{
		std::string value = stripHeaderName(header);
		size_t i = 0;
		while (i < value.size() && (value[i] == ' ' || value[i] == '\t')) ++i;
		uint32_t n = 0;
		bool any = false;
		while (i < value.size() && value[i] >= '0' && value[i] <= '9')
		{
			any = true;
			n = n * 10u + static_cast<uint32_t>(value[i] - '0');
			++i;
		}
		return any ? n : 0;
	}

	// Percent-decode a URI parameter value (RFC 3986 %XX escapes only — unlike
	// HTTP form encoding, a SIP URI parameter does NOT treat '+' as space, so an
	// intentional '+' in a Call-ID or tag survives unchanged). Used to decode the
	// ?Replaces=callid;from-tag=X;to-tag=Y URI parameter on an attended-transfer
	// Refer-To (RFC 3891) before the embedded ';' separators are parsed.
	inline std::string urlDecode(std::string_view src)
	{
		// Hand-rolled instead of sscanf("%x", ...): sscanf greedily matches a
		// variable-length run of hex digits, so a malformed escape like "%4Z"
		// (second char not hex) would parse just "4", report success, and the
		// caller's fixed pos += 2 would still skip both chars -- silently
		// dropping the literal 'Z' instead of emitting it. Require BOTH chars
		// to be hex before consuming either.
		auto hexVal = [](char c) -> int
		{
			if (c >= '0' && c <= '9') return c - '0';
			if (c >= 'a' && c <= 'f') return c - 'a' + 10;
			if (c >= 'A' && c <= 'F') return c - 'A' + 10;
			return -1;
		};
		std::string ret;
		ret.reserve(src.size());
		for (size_t pos = 0; pos < src.size(); ++pos)
		{
			if (src[pos] == '%' && pos + 2 < src.size())
			{
				int hi = hexVal(src[pos + 1]);
				int lo = hexVal(src[pos + 2]);
				if (hi >= 0 && lo >= 0)
				{
					ret += static_cast<char>((hi << 4) | lo);
					pos += 2;
					continue;
				}
			}
			ret += src[pos];
		}
		return ret;
	}
}

#endif
