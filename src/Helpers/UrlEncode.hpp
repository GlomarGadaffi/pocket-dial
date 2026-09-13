#ifndef POCKETDIAL_URL_ENCODE_HPP
#define POCKETDIAL_URL_ENCODE_HPP

#include <string>

// RFC 3986 percent-encoding for a single URL path/query component. The unreserved
// set (A-Z a-z 0-9 - _ . ~) passes through unchanged; every other byte is emitted
// as %XX with uppercase hex. Bytes are treated as unsigned so non-ASCII encodes
// correctly. Pure and host-compilable (no ESP/socket dependencies) so it is
// unit-tested in the host suite (tests/UrlEncode_test.cpp) and reused by the ESP
// Telephony anchor when building device-specific makecall URLs from a device_id that may
// carry reserved characters.
inline std::string urlEncode(const std::string& in)
{
	static const char kHex[] = "0123456789ABCDEF";
	std::string out;
	out.reserve(in.size());
	for (unsigned char c : in)
	{
		const bool unreserved =
			(c >= 'A' && c <= 'Z') ||
			(c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' || c == '~';
		if (unreserved)
		{
			out.push_back(static_cast<char>(c));
		}
		else
		{
			out.push_back('%');
			out.push_back(kHex[c >> 4]);
			out.push_back(kHex[c & 0x0F]);
		}
	}
	return out;
}

// Inverse of urlEncode: percent-decode a single URL component. '+' becomes a
// space (application/x-www-form-urlencoded convention); "%XX" with two hex
// digits becomes the decoded byte. A '%' NOT followed by two hex digits — a
// truncated escape ("%2", a trailing "%") or non-hex ("%zz") — is passed through
// literally, byte-for-byte, never silently swallowed.
//
// Trailing-escape bound (audit #73): a full "%XX" at the very end IS decoded.
// The two hex digits sit at pos+1 and pos+2; the last valid index is size()-1,
// so they both exist iff pos + 2 < size(). This is deliberately strict — relaxing
// it to "pos + 2 <= size()" would treat a one-digit "%2" as a valid escape (the
// missing third byte clamped away) and mangle malformed input. See
// tests/UrlEncode_test.cpp (UrlDecodeTrailingEscape).
inline std::string urlDecode(const std::string& src)
{
	auto hexVal = [](char c) -> int {
		if (c >= '0' && c <= '9') return c - '0';
		if (c >= 'a' && c <= 'f') return c - 'a' + 10;
		if (c >= 'A' && c <= 'F') return c - 'A' + 10;
		return -1;
	};
	std::string ret;
	ret.reserve(src.size());
	for (size_t pos = 0; pos < src.length(); ++pos)
	{
		const char c = src[pos];
		if (c == '+')
		{
			ret.push_back(' ');
		}
		else if (c == '%' && pos + 2 < src.length())
		{
			const int hi = hexVal(src[pos + 1]);
			const int lo = hexVal(src[pos + 2]);
			if (hi >= 0 && lo >= 0)
			{
				ret.push_back(static_cast<char>((hi << 4) | lo));
				pos += 2;
			}
			else
			{
				ret.push_back(c);   // not a valid %XX — pass the '%' through
			}
		}
		else
		{
			ret.push_back(c);
		}
	}
	return ret;
}

#endif // POCKETDIAL_URL_ENCODE_HPP
