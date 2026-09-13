#ifndef POCKETDIAL_JSON_ESCAPE_HPP
#define POCKETDIAL_JSON_ESCAPE_HPP

#include <string>

// RFC 8259 string-content escaping for a single JSON string value. Returns the
// escaped CONTENT only (no surrounding quotes) so callers can drop it between
// their own `"` delimiters: `"\"k\":\"" + jsonEscapeString(v) + "\""`.
//
// Escapes the two structurally-dangerous characters (`"` and `\`), the five
// short-form control escapes (\b \f \n \r \t), and every remaining C0 control
// byte (0x00-0x1F) as a \u00XX sequence. Bytes >= 0x20 other than `"`/`\` —
// including UTF-8 continuation bytes — pass through unchanged (RFC 8259 permits
// raw UTF-8 in JSON strings; only `"`, `\`, and U+0000..U+001F MUST be escaped).
//
// Pure and host-compilable (no ESP/socket dependencies) so it is unit-tested in
// the host suite (tests/JsonEscape_test.cpp) and reused by the ESP Telephony anchor
// when building the makecall control-plane POST body from a caller-supplied
// destination (issue #56 — defense-in-depth against JSON injection at the anchor
// boundary, independent of the upstream isValidAor input filter).
inline std::string jsonEscapeString(const std::string& in)
{
	static const char kHex[] = "0123456789abcdef";
	std::string out;
	out.reserve(in.size() + 8);
	for (unsigned char c : in)
	{
		switch (c)
		{
			case '"':  out += "\\\""; break;
			case '\\': out += "\\\\"; break;
			case '\b': out += "\\b";  break;
			case '\f': out += "\\f";  break;
			case '\n': out += "\\n";  break;
			case '\r': out += "\\r";  break;
			case '\t': out += "\\t";  break;
			default:
				if (c < 0x20)
				{
					// Remaining C0 control bytes -> \u00XX.
					out += "\\u00";
					out.push_back(kHex[(c >> 4) & 0x0F]);
					out.push_back(kHex[c & 0x0F]);
				}
				else
				{
					out.push_back(static_cast<char>(c));
				}
				break;
		}
	}
	return out;
}

#endif // POCKETDIAL_JSON_ESCAPE_HPP
