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

	// A "sip:" or "sips:" URI, the scheme in any case (RFC 3261 §19.1.4).
	inline bool hasSipScheme(std::string_view uri)
	{
		auto startsWith = [uri](std::string_view scheme) {
			if (uri.size() < scheme.size()) return false;
			for (size_t i = 0; i < scheme.size(); ++i)
			{
				if (std::tolower(static_cast<unsigned char>(uri[i])) != scheme[i]) return false;
			}
			return true;
		};
		return startsWith("sip:") || startsWith("sips:");
	}

	// The '<' that opens a name-addr's URI in a From/To/Contact line or value, or npos
	// (an addr-spec, or nothing). #824: a '<' inside a quoted string is not the URI's
	// (RFC 3261 §25.1 quoted-string, \-escapes included), so with balanced quotes it is
	// the first '<' outside them. `open` is set when a quote is left open (an unescaped
	// '"' in a display name, "Lobby 55" TV"). #832, #835: then it is the first '<'
	// outside quotes if only header parameters follow its '>'; else the last '<'
	// outside quotes counted from the right, where a parameter's quoted value
	// (+sip.instance="<urn:...>") pairs up whatever the display name left open; else
	// the last '<' on the line.
	inline size_t nameAddrOpen(std::string_view v, bool& open)
	{
		size_t first = std::string_view::npos;
		bool quoted = false;
		for (size_t i = 0; i < v.size(); ++i)
		{
			const char c = v[i];
			if (quoted)
			{
				if (c == '\\') ++i;
				else if (c == '"') quoted = false;
			}
			else if (c == '"')
			{
				quoted = true;
			}
			else if (c == '<' && first == std::string_view::npos)
			{
				first = i;
			}
		}
		open = quoted;
		if (!quoted) return first;
		if (first != std::string_view::npos)
		{
			size_t after = v.find('>', first + 1);
			if (after != std::string_view::npos)
			{
				++after;
				while (after < v.size() && (v[after] == ' ' || v[after] == '\t' || v[after] == '\r' || v[after] == '\n')) ++after;
				if (after == v.size() || v[after] == ';' || v[after] == ',') return first;
			}
		}
		bool rquoted = false;
		for (size_t i = v.size(); i-- > 0;)
		{
			const char c = v[i];
			if (c == '"')
			{
				size_t slashes = 0;
				while (slashes < i && v[i - 1 - slashes] == '\\') ++slashes;
				if (!rquoted || slashes % 2 == 0) rquoted = !rquoted;
			}
			else if (c == '<' && !rquoted)
			{
				return i;
			}
		}
		return v.rfind('<');
	}

	// The bare URI of a Contact header line, parameters of the URI kept ("sip:1001@h:5060;line=x"
	// out of "Contact: <sip:1001@h:5060;line=x>;reg-id=1"). A bare, unbracketed URI is cut at the
	// first ';' (header parameters, RFC 3261 §20.10). A view into `header`; empty when none.
	// Which <...> is the URI: nameAddrOpen(). A quote left open with no '<' gives empty.
	inline std::string_view contactUriView(std::string_view header)
	{
		std::string_view v = stripHeaderNameView(header);
		bool open = false;
		const size_t lt = nameAddrOpen(v, open);
		if (lt != std::string_view::npos)
		{
			const size_t gt = v.find('>', lt + 1);
			return gt == std::string_view::npos ? std::string_view{} : v.substr(lt + 1, gt - lt - 1);
		}
		if (open) return {};
		const size_t semi = v.find(';');
		if (semi != std::string_view::npos) v = v.substr(0, semi);
		while (!v.empty() && (v.front() == ' ' || v.front() == '\t')) v.remove_prefix(1);
		while (!v.empty() && (v.back() == ' ' || v.back() == '\t')) v.remove_suffix(1);
		return v;
	}

	// Parse the leading digits out of a CSeq header line ("CSeq: 100 INVITE")
	// or an already-stripped value ("100 INVITE") -- either form works, since
	// this strips the header name itself first. Returns 0 on anything
	// unparseable; callers must treat 0 as "absent/unknown", never as a real
	// CSeq value (RFC 3261 places no floor on where a UA's own counter starts,
	// but a well-formed request always has SOME digits here).
	inline uint32_t cseqNumber(std::string_view header)
	{
		const std::string_view value = stripHeaderNameView(header);   // no per-request copy
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
