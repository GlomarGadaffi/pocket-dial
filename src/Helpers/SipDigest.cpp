// SipDigest.cpp — self-contained SIP HTTP-Digest primitives (RFC 2617, MD5 only;
// RFC 8760 SHA-256 is not implemented — see SipDigest.hpp).
//
// See SipDigest.hpp for the design rationale. This file is intentionally
// dependency-free beyond the C++17 standard library and the platform guards.
//
// Crypto: a small, self-contained MD5 (public-domain reference of RFC 1321) is
// used on BOTH host and ESP so the digest is identical and portable, and so the
// host build needs no external crypto library. IDF v6.0.1 only exposes
// mbedtls/private/md5.h (PSA layout), so vendoring a portable MD5 is both more
// robust and avoids reaching into a private header.
//
// Randomness (for the nonce server-secret): esp_random() (hardware CSPRNG) on
// ESP; on host, a std::random_device-seeded std::mt19937_64 (host is a
// developer/CI simulator, not the production trust boundary).

#include "SipDigest.hpp"

#include <array>
#include <cstring>
#include <cctype>
#include <chrono>
#include <initializer_list>
#include <mutex>
#include <string_view>
#include <vector>

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	#include "esp_random.h"
#else
	#include <random>
#endif

namespace
{
	// =====================================================================
	// Self-contained MD5 (RFC 1321). Public-domain reference style.
	// Operates on bytes; produces a 16-byte digest. NOTE: MD5 is used here
	// ONLY as the digest-auth construction RFC 2617 mandates — it is not a
	// general-purpose secure hash, and the per-extension secret store
	// documents that HA1-at-rest wants flash encryption (follow-up).
	// =====================================================================
	class Md5
	{
	public:
		Md5() { reset(); }

		void update(const uint8_t* data, size_t len)
		{
			size_t i = 0;
			// Number of bytes already buffered (0..63).
			size_t index = static_cast<size_t>((_count >> 3) & 0x3F);
			_count += static_cast<uint64_t>(len) << 3;
			size_t partLen = 64 - index;

			if (len >= partLen)
			{
				std::memcpy(&_buffer[index], data, partLen);
				transform(_buffer.data());
				for (i = partLen; i + 63 < len; i += 64)
				{
					transform(&data[i]);
				}
				index = 0;
			}
			std::memcpy(&_buffer[index], &data[i], len - i);
		}

		void update(const std::string& s)
		{
			update(reinterpret_cast<const uint8_t*>(s.data()), s.size());
		}

		void finalize(uint8_t out[16])
		{
			// Save the bit length before padding.
			uint8_t bits[8];
			for (int b = 0; b < 8; ++b)
			{
				bits[b] = static_cast<uint8_t>((_count >> (b * 8)) & 0xFF);
			}

			// Pad: append 0x80 then zeros until length ≡ 56 (mod 64).
			size_t index = static_cast<size_t>((_count >> 3) & 0x3F);
			size_t padLen = (index < 56) ? (56 - index) : (120 - index);
			static const uint8_t kPad[64] = { 0x80 };
			update(kPad, padLen);

			// Append the 64-bit little-endian length.
			update(bits, 8);

			// Emit state little-endian.
			for (int j = 0; j < 4; ++j)
			{
				out[j * 4 + 0] = static_cast<uint8_t>(_state[j] & 0xFF);
				out[j * 4 + 1] = static_cast<uint8_t>((_state[j] >> 8) & 0xFF);
				out[j * 4 + 2] = static_cast<uint8_t>((_state[j] >> 16) & 0xFF);
				out[j * 4 + 3] = static_cast<uint8_t>((_state[j] >> 24) & 0xFF);
			}
		}

	private:
		void reset()
		{
			_state[0] = 0x67452301u;
			_state[1] = 0xefcdab89u;
			_state[2] = 0x98badcfeu;
			_state[3] = 0x10325476u;
			_count = 0;
		}

		static uint32_t rotl(uint32_t x, int n)
		{
			return (x << n) | (x >> (32 - n));
		}

		void transform(const uint8_t block[64])
		{
			uint32_t a = _state[0], b = _state[1], c = _state[2], d = _state[3];
			uint32_t x[16];
			for (int i = 0; i < 16; ++i)
			{
				x[i] = (static_cast<uint32_t>(block[i * 4 + 0])) |
				       (static_cast<uint32_t>(block[i * 4 + 1]) << 8) |
				       (static_cast<uint32_t>(block[i * 4 + 2]) << 16) |
				       (static_cast<uint32_t>(block[i * 4 + 3]) << 24);
			}

			auto F = [](uint32_t xx, uint32_t yy, uint32_t zz) { return (xx & yy) | (~xx & zz); };
			auto G = [](uint32_t xx, uint32_t yy, uint32_t zz) { return (xx & zz) | (yy & ~zz); };
			auto H = [](uint32_t xx, uint32_t yy, uint32_t zz) { return xx ^ yy ^ zz; };
			auto I = [](uint32_t xx, uint32_t yy, uint32_t zz) { return yy ^ (xx | ~zz); };

			auto step = [&](auto fn, uint32_t& wa, uint32_t wb, uint32_t wc, uint32_t wd,
			                uint32_t xk, int s, uint32_t ac) {
				wa = wa + fn(wb, wc, wd) + xk + ac;
				wa = rotl(wa, s);
				wa = wa + wb;
			};

			// Round 1
			step(F, a, b, c, d, x[ 0],  7, 0xd76aa478u); step(F, d, a, b, c, x[ 1], 12, 0xe8c7b756u);
			step(F, c, d, a, b, x[ 2], 17, 0x242070dbu); step(F, b, c, d, a, x[ 3], 22, 0xc1bdceeeu);
			step(F, a, b, c, d, x[ 4],  7, 0xf57c0fafu); step(F, d, a, b, c, x[ 5], 12, 0x4787c62au);
			step(F, c, d, a, b, x[ 6], 17, 0xa8304613u); step(F, b, c, d, a, x[ 7], 22, 0xfd469501u);
			step(F, a, b, c, d, x[ 8],  7, 0x698098d8u); step(F, d, a, b, c, x[ 9], 12, 0x8b44f7afu);
			step(F, c, d, a, b, x[10], 17, 0xffff5bb1u); step(F, b, c, d, a, x[11], 22, 0x895cd7beu);
			step(F, a, b, c, d, x[12],  7, 0x6b901122u); step(F, d, a, b, c, x[13], 12, 0xfd987193u);
			step(F, c, d, a, b, x[14], 17, 0xa679438eu); step(F, b, c, d, a, x[15], 22, 0x49b40821u);

			// Round 2
			step(G, a, b, c, d, x[ 1],  5, 0xf61e2562u); step(G, d, a, b, c, x[ 6],  9, 0xc040b340u);
			step(G, c, d, a, b, x[11], 14, 0x265e5a51u); step(G, b, c, d, a, x[ 0], 20, 0xe9b6c7aau);
			step(G, a, b, c, d, x[ 5],  5, 0xd62f105du); step(G, d, a, b, c, x[10],  9, 0x02441453u);
			step(G, c, d, a, b, x[15], 14, 0xd8a1e681u); step(G, b, c, d, a, x[ 4], 20, 0xe7d3fbc8u);
			step(G, a, b, c, d, x[ 9],  5, 0x21e1cde6u); step(G, d, a, b, c, x[14],  9, 0xc33707d6u);
			step(G, c, d, a, b, x[ 3], 14, 0xf4d50d87u); step(G, b, c, d, a, x[ 8], 20, 0x455a14edu);
			step(G, a, b, c, d, x[13],  5, 0xa9e3e905u); step(G, d, a, b, c, x[ 2],  9, 0xfcefa3f8u);
			step(G, c, d, a, b, x[ 7], 14, 0x676f02d9u); step(G, b, c, d, a, x[12], 20, 0x8d2a4c8au);

			// Round 3
			step(H, a, b, c, d, x[ 5],  4, 0xfffa3942u); step(H, d, a, b, c, x[ 8], 11, 0x8771f681u);
			step(H, c, d, a, b, x[11], 16, 0x6d9d6122u); step(H, b, c, d, a, x[14], 23, 0xfde5380cu);
			step(H, a, b, c, d, x[ 1],  4, 0xa4beea44u); step(H, d, a, b, c, x[ 4], 11, 0x4bdecfa9u);
			step(H, c, d, a, b, x[ 7], 16, 0xf6bb4b60u); step(H, b, c, d, a, x[10], 23, 0xbebfbc70u);
			step(H, a, b, c, d, x[13],  4, 0x289b7ec6u); step(H, d, a, b, c, x[ 0], 11, 0xeaa127fau);
			step(H, c, d, a, b, x[ 3], 16, 0xd4ef3085u); step(H, b, c, d, a, x[ 6], 23, 0x04881d05u);
			step(H, a, b, c, d, x[ 9],  4, 0xd9d4d039u); step(H, d, a, b, c, x[12], 11, 0xe6db99e5u);
			step(H, c, d, a, b, x[15], 16, 0x1fa27cf8u); step(H, b, c, d, a, x[ 2], 23, 0xc4ac5665u);

			// Round 4
			step(I, a, b, c, d, x[ 0],  6, 0xf4292244u); step(I, d, a, b, c, x[ 7], 10, 0x432aff97u);
			step(I, c, d, a, b, x[14], 15, 0xab9423a7u); step(I, b, c, d, a, x[ 5], 21, 0xfc93a039u);
			step(I, a, b, c, d, x[12],  6, 0x655b59c3u); step(I, d, a, b, c, x[ 3], 10, 0x8f0ccc92u);
			step(I, c, d, a, b, x[10], 15, 0xffeff47du); step(I, b, c, d, a, x[ 1], 21, 0x85845dd1u);
			step(I, a, b, c, d, x[ 8],  6, 0x6fa87e4fu); step(I, d, a, b, c, x[15], 10, 0xfe2ce6e0u);
			step(I, c, d, a, b, x[ 6], 15, 0xa3014314u); step(I, b, c, d, a, x[13], 21, 0x4e0811a1u);
			step(I, a, b, c, d, x[ 4],  6, 0xf7537e82u); step(I, d, a, b, c, x[11], 10, 0xbd3af235u);
			step(I, c, d, a, b, x[ 2], 15, 0x2ad7d2bbu); step(I, b, c, d, a, x[ 9], 21, 0xeb86d391u);

			_state[0] += a;
			_state[1] += b;
			_state[2] += c;
			_state[3] += d;
		}

		std::array<uint32_t, 4> _state{};
		std::array<uint8_t, 64>  _buffer{};
		uint64_t _count = 0;   // message length in BITS
	};

	std::string toHex(const uint8_t* data, size_t len)
	{
		static const char* digits = "0123456789abcdef";
		std::string out;
		out.reserve(len * 2);
		for (size_t i = 0; i < len; ++i)
		{
			out.push_back(digits[(data[i] >> 4) & 0x0F]);
			out.push_back(digits[data[i] & 0x0F]);
		}
		return out;
	}

	// HMAC-MD5 (RFC 2104) -> 32-char lowercase hex. A real HMAC, NOT the
	// length-extension-forgeable MD5(secret || message) construction. Used to tag
	// the stateless nonce so an attacker who observes a nonce cannot forge a valid
	// tag for a different timestamp.
	std::string hmacMd5Hex(const std::string& key, const std::string& msg)
	{
		constexpr size_t BLOCK = 64;
		uint8_t k[BLOCK] = {0};
		if (key.size() > BLOCK)
		{
			Md5 kh;
			uint8_t kd[16];
			kh.update(key);
			kh.finalize(kd);
			std::memcpy(k, kd, sizeof(kd));
		}
		else
		{
			std::memcpy(k, key.data(), key.size());
		}

		uint8_t ipad[BLOCK];
		uint8_t opad[BLOCK];
		for (size_t i = 0; i < BLOCK; ++i)
		{
			ipad[i] = static_cast<uint8_t>(k[i] ^ 0x36);
			opad[i] = static_cast<uint8_t>(k[i] ^ 0x5c);
		}

		uint8_t inner[16];
		{
			Md5 h;
			h.update(ipad, BLOCK);
			h.update(reinterpret_cast<const uint8_t*>(msg.data()), msg.size());
			h.finalize(inner);
		}
		uint8_t outer[16];
		{
			Md5 h;
			h.update(opad, BLOCK);
			h.update(inner, sizeof(inner));
			h.finalize(outer);
		}
		return toHex(outer, sizeof(outer));
	}

	// Cryptographically-strong (on ESP) random bytes; on host, a PRNG seeded from
	// random_device (host is a developer/CI simulator). Mirrors AdminAuth.
	void fillRandom(uint8_t* buf, size_t len)
	{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
		for (size_t i = 0; i < len; ++i)
		{
			buf[i] = static_cast<uint8_t>(esp_random() & 0xFF);
		}
#else
		static std::mt19937_64 rng = [] {
			std::random_device rd;
			uint64_t seed = (static_cast<uint64_t>(rd()) << 32) ^ rd();
			seed ^= static_cast<uint64_t>(
				std::chrono::steady_clock::now().time_since_epoch().count());
			return std::mt19937_64(seed);
		}();
		for (size_t i = 0; i < len; ++i)
		{
			buf[i] = static_cast<uint8_t>(rng() & 0xFF);
		}
#endif
	}

	uint64_t nowMs()
	{
		return static_cast<uint64_t>(
			std::chrono::duration_cast<std::chrono::milliseconds>(
				std::chrono::system_clock::now().time_since_epoch()).count());
	}

	// Constant-time string compare. Returns true iff equal. Does not short-circuit
	// on the first differing byte. (Length is compared up front; the response hex
	// digests we compare are always the same fixed length.)
	bool constantTimeEquals(const std::string& a, const std::string& b)
	{
		if (a.size() != b.size())
		{
			return false;
		}
		unsigned char diff = 0;
		for (size_t i = 0; i < a.size(); ++i)
		{
			diff = static_cast<unsigned char>(
				diff | (static_cast<unsigned char>(a[i]) ^ static_cast<unsigned char>(b[i])));
		}
		return diff == 0;
	}

	// Process-lifetime server secret keying the nonce tag. Generated once on first
	// use. A reboot rotates it — that simply invalidates outstanding nonces, which
	// clients transparently recover from via a fresh 401 challenge.
	const std::string& nonceServerSecret()
	{
		static std::string secret = [] {
			uint8_t raw[32];
			fillRandom(raw, sizeof(raw));
			return toHex(raw, sizeof(raw));
		}();
		return secret;
	}

	// Strip surrounding whitespace and a single pair of double-quotes.
	//
	// Returns a VIEW into `sv`, not a copy. It only ever narrows its input, so a
	// std::string here was an allocation that bought nothing -- and it sat on the
	// digest client's wire path, which #399 requires to be heap-free. Callers
	// must not let the result outlive the buffer `sv` points into.
	std::string_view trimQuoted(std::string_view sv)
	{
		size_t b = 0, e = sv.size();
		while (b < e && std::isspace(static_cast<unsigned char>(sv[b]))) ++b;
		while (e > b && std::isspace(static_cast<unsigned char>(sv[e - 1]))) --e;
		if (e - b >= 2 && sv[b] == '"' && sv[e - 1] == '"')
		{
			++b;
			--e;
		}
		return sv.substr(b, e - b);
	}

	bool iequalsAscii(std::string_view a, std::string_view b)
	{
		if (a.size() != b.size()) return false;
		for (size_t i = 0; i < a.size(); ++i)
		{
			if (std::tolower(static_cast<unsigned char>(a[i])) !=
			    std::tolower(static_cast<unsigned char>(b[i]))) return false;
		}
		return true;
	}

	// =====================================================================
	// ONE parameter scanner, shared by both directions.
	//
	// parseAuthorization() (server: read a client's credential) and
	// parseChallenge() (client: read a server's challenge) parse the SAME
	// production — RFC 7235's comma-separated auth-param list, with values that
	// are either a quoted-string or a bare token, in any order, with arbitrary
	// whitespace. The ONLY thing that differs between the two is which keys each
	// side stores. So the scanner is generic over a per-parameter callback and
	// the header names that may legally prefix the value.
	//
	// This was extracted from parseAuthorization rather than duplicated: the
	// quoting rules here are subtle (a quoted value may legally contain a comma,
	// which is why splitting on commas first is wrong), and a second copy would
	// have inherited today's bugs without inheriting tomorrow's fixes. The
	// scanning behaviour is byte-for-byte the code parseAuthorization already
	// shipped — the refactor is a move, not a rewrite.
	//
	// `names`        : header names that may prefix the value; "Digest ..." bare
	//                  is always accepted too.
	// `matchedName`  : if non-null, set to the name that was stripped, or left
	//                  empty when the value carried no header name.
	// `fn(key,value)`: invoked once per parameter. `key` is whitespace-trimmed
	//                  but case-preserved; `value` is already unquoted.
	//
	// ALLOCATION-FREE (#399). Both `key` and `value` are VIEWS into
	// `headerValue`, valid only for the duration of the callback: a callback
	// that needs to keep a value must copy it out before returning. That is
	// what lets one scanner serve the std::string API (which copies into
	// std::string members) and the bounded client API (which copies into fixed
	// char buffers) without either paying for the other's representation. It is
	// sound because no quoted value is escape-processed here -- a quoted value
	// is the literal bytes between the quotes, so it is always a substring.
	//
	// Returns false iff the "Digest" scheme token is absent.
	template <typename Fn>
	bool scanDigestParams(std::string_view headerValue,
	                      std::initializer_list<std::string_view> names,
	                      std::string_view* matchedName,
	                      Fn&& fn)
	{
		if (matchedName) *matchedName = std::string_view{};

		std::string_view sv(headerValue);

		// Drop an optional header name.
		size_t colon = sv.find(':');
		if (colon != std::string_view::npos)
		{
			std::string_view name = sv.substr(0, colon);
			// Only strip if it actually looks like the header name (no '=' before
			// the colon, which would indicate this colon belongs to a param value).
			if (name.find('=') == std::string_view::npos)
			{
				const std::string_view trimmed = trimQuoted(name);
				for (std::string_view candidate : names)
				{
					if (iequalsAscii(trimmed, candidate))
					{
						if (matchedName) *matchedName = candidate;
						sv = sv.substr(colon + 1);
						break;
					}
				}
			}
		}

		// Skip leading whitespace.
		size_t p = 0;
		while (p < sv.size() && std::isspace(static_cast<unsigned char>(sv[p]))) ++p;

		// Require the "Digest" scheme token.
		static const std::string_view kScheme = "digest";
		if (p + kScheme.size() > sv.size() ||
		    !iequalsAscii(sv.substr(p, kScheme.size()), kScheme))
		{
			return false;
		}
		p += kScheme.size();

		// Parse comma-separated key=value pairs. Values may be quoted (and a quoted
		// value may legally contain a comma), so honor quoting while splitting.
		std::string_view rest = sv.substr(p);
		size_t i = 0;
		const size_t n = rest.size();
		while (i < n)
		{
			// Skip separators/whitespace.
			while (i < n && (std::isspace(static_cast<unsigned char>(rest[i])) || rest[i] == ',')) ++i;
			if (i >= n) break;

			// Key up to '='.
			size_t keyStart = i;
			while (i < n && rest[i] != '=' && rest[i] != ',') ++i;
			if (i >= n || rest[i] != '=')
			{
				// Malformed token without a value — skip to next comma.
				while (i < n && rest[i] != ',') ++i;
				continue;
			}
			std::string_view key = rest.substr(keyStart, i - keyStart);
			++i; // consume '='

			// Value: quoted or bare token (terminated by an unquoted comma).
			std::string_view value;
			while (i < n && std::isspace(static_cast<unsigned char>(rest[i]))) ++i;
			if (i < n && rest[i] == '"')
			{
				++i; // opening quote
				size_t valStart = i;
				while (i < n && rest[i] != '"') ++i;
				value = rest.substr(valStart, i - valStart);
				if (i < n) ++i; // closing quote
			}
			else
			{
				size_t valStart = i;
				while (i < n && rest[i] != ',') ++i;
				value = trimQuoted(rest.substr(valStart, i - valStart));
			}

			std::string_view k = key;
			// Trim any whitespace around the key.
			while (!k.empty() && std::isspace(static_cast<unsigned char>(k.front()))) k.remove_prefix(1);
			while (!k.empty() && std::isspace(static_cast<unsigned char>(k.back())))  k.remove_suffix(1);

			fn(k, value);
		}

		return true;
	}
}

namespace SipDigest
{
	std::string md5Hex(const std::string& input)
	{
		uint8_t digest[16];
		Md5 md;
		md.update(input);
		md.finalize(digest);
		return toHex(digest, sizeof(digest));
	}

	std::string buildWwwAuthenticate(const std::string& realm,
	                                 const std::string& nonce,
	                                 bool stale)
	{
		std::string out = "Digest realm=\"" + realm + "\", nonce=\"" + nonce +
		                  "\", qop=\"auth\", algorithm=MD5";
		if (stale)
		{
			out += ", stale=true";
		}
		return out;
	}

	bool parseAuthorization(const std::string& authHeaderValue, DigestAuth& out)
	{
		out = DigestAuth{};

		// Only "authorization" is accepted as a strippable header name, exactly as
		// before this was refactored onto the shared scanner. Widening it to
		// Proxy-Authorization would be a behaviour change for every existing
		// caller (a full "Proxy-Authorization: ..." line used to fail the scheme
		// check and return false), and the registrar has no proxy role to need it.
		const bool isDigest = scanDigestParams(
			authHeaderValue, {"authorization"}, nullptr,
			[&out](std::string_view k, std::string_view value) {
				if      (iequalsAscii(k, "username"))  out.username  = value;
				else if (iequalsAscii(k, "realm"))     out.realm     = value;
				else if (iequalsAscii(k, "nonce"))     out.nonce     = value;
				else if (iequalsAscii(k, "uri"))       out.uri       = value;
				else if (iequalsAscii(k, "response"))  out.response  = value;
				else if (iequalsAscii(k, "qop"))       out.qop       = value;
				else if (iequalsAscii(k, "nc"))        out.nc        = value;
				else if (iequalsAscii(k, "cnonce"))    out.cnonce    = value;
				else if (iequalsAscii(k, "algorithm")) out.algorithm = value;
				else if (iequalsAscii(k, "opaque"))    out.opaque    = value;
				// Unknown parameters are ignored (forward-compatible).
			});
		if (!isDigest)
		{
			return false;
		}

		return !out.username.empty() && !out.response.empty();
	}

	std::string computeHa1(const std::string& ext,
	                       const std::string& realm,
	                       const std::string& secret)
	{
		return md5Hex(ext + ":" + realm + ":" + secret);
	}

	std::string computeResponse(const std::string& ha1,
	                            const std::string& method,
	                            const std::string& uri,
	                            const std::string& nonce,
	                            const std::string& nc,
	                            const std::string& cnonce,
	                            const std::string& qop)
	{
		std::string ha2 = md5Hex(method + ":" + uri);
		if (qop.empty())
		{
			// Legacy RFC 2069: response = MD5(HA1:nonce:HA2).
			return md5Hex(ha1 + ":" + nonce + ":" + ha2);
		}
		// RFC 2617 qop="auth": MD5(HA1:nonce:nc:cnonce:qop:HA2).
		return md5Hex(ha1 + ":" + nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + ha2);
	}

	bool verify(const DigestAuth& auth,
	            const std::string& ha1,
	            const std::string& method)
	{
		if (auth.response.empty() || ha1.empty())
		{
			return false;
		}
		std::string expected = computeResponse(ha1, method, auth.uri, auth.nonce,
		                                        auth.nc, auth.cnonce, auth.qop);
		return constantTimeEquals(expected, auth.response);
	}

	// --- Nonce helper -----------------------------------------------------

	namespace
	{
		std::string nonceTag(uint64_t tsMs)
		{
			// HMAC-MD5 over the timestamp, keyed by the process-lifetime server
			// secret. A true HMAC (not MD5(secret || msg)) so the tag is not
			// length-extension forgeable. The secret is never transmitted and
			// rotates on reboot.
			return hmacMd5Hex(nonceServerSecret(), std::to_string(tsMs));
		}

		std::string toHexU64(uint64_t v)
		{
			static const char* d = "0123456789abcdef";
			char buf[16];
			for (int i = 15; i >= 0; --i)
			{
				buf[i] = d[v & 0xF];
				v >>= 4;
			}
			return std::string(buf, 16);
		}

		bool fromHexU64(std::string_view sv, uint64_t& out)
		{
			if (sv.empty() || sv.size() > 16) return false;
			uint64_t v = 0;
			for (char c : sv)
			{
				v <<= 4;
				if (c >= '0' && c <= '9')       v |= static_cast<uint64_t>(c - '0');
				else if (c >= 'a' && c <= 'f')  v |= static_cast<uint64_t>(c - 'a' + 10);
				else if (c >= 'A' && c <= 'F')  v |= static_cast<uint64_t>(c - 'A' + 10);
				else return false;
			}
			out = v;
			return true;
		}
	}

	std::string generateNonce()
	{
		uint64_t ts = nowMs();
		return toHexU64(ts) + "." + nonceTag(ts);
	}

	bool validateNonce(const std::string& nonce, bool* expiredOut, uint64_t ttlMs)
	{
		if (expiredOut) *expiredOut = false;

		size_t dot = nonce.find('.');
		if (dot == std::string::npos)
		{
			return false;
		}
		std::string_view nonceView(nonce);
		std::string_view tsHex = nonceView.substr(0, dot);
		std::string_view tag = nonceView.substr(dot + 1);

		uint64_t ts = 0;
		if (!fromHexU64(tsHex, ts))
		{
			return false;
		}

		// Integrity: recompute the tag and constant-time compare.
		if (!constantTimeEquals(nonceTag(ts), std::string(tag)))
		{
			return false; // forged / corrupt — NOT stale
		}

		// Freshness. Guard against clock skew making `now < ts`.
		uint64_t now = nowMs();
		uint64_t age = (now >= ts) ? (now - ts) : 0;
		bool expired = age > ttlMs;
		if (expiredOut) *expiredOut = expired;
		return !expired;
	}

	bool isStale(const std::string& nonce, uint64_t ttlMs)
	{
		bool expired = false;
		bool fresh = validateNonce(nonce, &expired, ttlMs);
		// Stale = the tag verified (it's ours) but it timed out.
		// validateNonce returns false-with-expired=true in exactly that case.
		return !fresh && expired;
	}

	// =====================================================================
	// CLIENT SIDE (UAC)
	// =====================================================================

	bool parseChallenge(const std::string& challengeHeaderValue,
	                    DigestChallenge& out,
	                    bool proxyDefault)
	{
		out = DigestChallenge{};
		out.proxy = proxyDefault;

		std::string_view matched;
		const bool isDigest = scanDigestParams(
			challengeHeaderValue, {"www-authenticate", "proxy-authenticate"}, &matched,
			[&out](std::string_view k, std::string_view value) {
				if      (iequalsAscii(k, "realm"))     out.realm       = value;
				else if (iequalsAscii(k, "nonce"))     out.nonce       = value;
				else if (iequalsAscii(k, "opaque"))    out.opaque      = value;
				else if (iequalsAscii(k, "algorithm")) out.algorithm   = value;
				else if (iequalsAscii(k, "qop"))       out.qopList     = value;
				else if (iequalsAscii(k, "domain"))    out.domainParam = value;
				else if (iequalsAscii(k, "stale"))
				{
					// RFC 7616 §3.3: stale is an unquoted token, but plenty of
					// stacks quote it. The scanner has already unquoted, so a
					// plain case-insensitive "true" is the whole test.
					out.stale = iequalsAscii(value, "true");
				}
				// Unknown parameters are ignored (forward-compatible).
			});
		if (!isDigest)
		{
			return false;
		}

		// A header name that was actually present overrides proxyDefault.
		if (!matched.empty())
		{
			out.proxy = iequalsAscii(matched, "proxy-authenticate");
		}

		// A challenge with no nonce is unanswerable: there is nothing to hash
		// against, and emitting a response over an empty nonce would produce a
		// digest the server can never reproduce. A realm-less challenge, by
		// contrast, is answerable — HA1 just hashes an empty realm, which is what
		// the server that omitted it must itself do.
		return !out.nonce.empty();
	}

	DigestAlgorithm algorithmOf(const DigestChallenge& ch)
	{
		if (ch.algorithm.empty())                    return DigestAlgorithm::Md5;
		if (iequalsAscii(ch.algorithm, "md5"))       return DigestAlgorithm::Md5;
		if (iequalsAscii(ch.algorithm, "md5-sess"))  return DigestAlgorithm::Md5Sess;
		// SHA-256 / SHA-512-256 / SHA-*-sess (RFC 8760) and anything unrecognised.
		return DigestAlgorithm::Unsupported;
	}

	bool selectQop(const DigestChallenge& ch, std::string& out)
	{
		out.clear();

		// No qop parameter at all -> legacy RFC 2069. Answer with the short form.
		if (ch.qopList.empty())
		{
			return true;
		}

		// qop is a comma-separated list of tokens ("auth", "auth-int", or a
		// server extension). Walk it and take "auth" if it is offered.
		//
		// The substring trap this avoids: `qopList.find("auth") != npos` is true
		// for an auth-int-ONLY challenge, because "auth-int" contains "auth". A
		// client that fell for that would send qop=auth against a server that
		// never offered it.
		size_t i = 0;
		const size_t n = ch.qopList.size();
		while (i < n)
		{
			while (i < n && (ch.qopList[i] == ',' ||
			                 std::isspace(static_cast<unsigned char>(ch.qopList[i])))) ++i;
			size_t start = i;
			while (i < n && ch.qopList[i] != ',') ++i;
			size_t end = i;
			while (end > start &&
			       std::isspace(static_cast<unsigned char>(ch.qopList[end - 1]))) --end;
			if (iequalsAscii(std::string_view(ch.qopList).substr(start, end - start), "auth"))
			{
				out = "auth";
				return true;
			}
		}

		// A list was offered and "auth" is not in it — auth-int only, or something
		// we do not implement. Refuse rather than guess.
		return false;
	}

	std::string computeHa1Sess(const std::string& ha1,
	                           const std::string& nonce,
	                           const std::string& cnonce)
	{
		return md5Hex(ha1 + ":" + nonce + ":" + cnonce);
	}

	const char* authorizationHeaderName(const DigestChallenge& ch)
	{
		return ch.proxy ? "Proxy-Authorization" : "Authorization";
	}

	std::string formatNc(uint32_t count)
	{
		static const char* d = "0123456789abcdef";
		char buf[8];
		uint32_t v = count;
		for (int i = 7; i >= 0; --i)
		{
			buf[i] = d[v & 0xF];
			v >>= 4;
		}
		return std::string(buf, 8);
	}

	std::string makeCnonce()
	{
		uint8_t raw[8];
		fillRandom(raw, sizeof(raw));
		return toHex(raw, sizeof(raw));
	}

	bool buildAuthorization(const DigestChallenge& ch,
	                        const std::string& username,
	                        const std::string& password,
	                        const std::string& method,
	                        const std::string& uri,
	                        uint32_t ncValue,
	                        const std::string& cnonce,
	                        std::string& out)
	{
		// --- Refusal gates. Each one is a case where answering anyway produces a
		// --- response the server will reject forever, with no diagnostic.

		if (ch.nonce.empty())
		{
			return false;
		}

		const DigestAlgorithm alg = algorithmOf(ch);
		if (alg == DigestAlgorithm::Unsupported)
		{
			// RFC 8760 SHA-256 / SHA-512-256. We vendor only MD5 (see the file
			// header), and an MD5 response to a SHA-256 challenge is simply wrong.
			return false;
		}

		std::string qop;
		if (!selectQop(ch, qop))
		{
			// auth-int only: the response would have to hash the message body,
			// which this implementation does not do.
			return false;
		}

		if (!qop.empty() && cnonce.empty())
		{
			// qop=auth REQUIRES a cnonce (RFC 7616 §3.4). An empty one hashes,
			// but it destroys the client-nonce's entire purpose and some SBCs
			// reject it outright.
			return false;
		}

		if (alg == DigestAlgorithm::Md5Sess && cnonce.empty())
		{
			// HA1-sess is defined over the cnonce; without one there is no HA1.
			return false;
		}

		if (alg == DigestAlgorithm::Md5Sess && qop.empty())
		{
			// MD5-sess with NO qop is the one combination that cannot be made to
			// work, and it is worth spelling out because it looks answerable.
			// HA1-sess is MD5(HA1:nonce:cnonce), so the server needs our cnonce to
			// recompute it — but the legacy no-qop emission omits cnonce entirely
			// (and RFC 2617 says a cnonce MUST NOT be sent without qop). Either
			// way the server cannot reproduce the digest.
			//
			// Answering anyway would be exactly the "silently compute the wrong
			// thing" failure the SHA-2 refusal above exists to prevent: a
			// well-formed header carrying a response nobody can verify. A server
			// that really wants MD5-sess has to offer qop.
			return false;
		}

		// --- Compute.

		std::string ha1 = computeHa1(username, ch.realm, password);
		if (alg == DigestAlgorithm::Md5Sess)
		{
			ha1 = computeHa1Sess(ha1, ch.nonce, cnonce);
		}

		const std::string nc = formatNc(ncValue);
		const std::string response =
			computeResponse(ha1, method, uri, ch.nonce, nc, cnonce, qop);

		// --- Emit. Quoting follows RFC 7616 §3.4's ABNF: username/realm/nonce/
		// --- uri/response/cnonce/opaque are quoted-string, algorithm/qop/nc are
		// --- bare tokens. Quoting nc or qop is the single most common emit bug —
		// --- Kamailio and several SBCs reject a quoted nc outright.
		out  = "Digest username=\"" + username + "\"";
		out += ", realm=\"" + ch.realm + "\"";
		out += ", nonce=\"" + ch.nonce + "\"";
		out += ", uri=\"" + uri + "\"";
		out += ", response=\"" + response + "\"";

		// Echo the algorithm ONLY when the challenge named one. An RFC 2069 server
		// that sent no algorithm gets no algorithm back, which is exactly what the
		// RFC 2617 §3.5 worked example shows the client sending.
		if (!ch.algorithm.empty())
		{
			out += ", algorithm=" + ch.algorithm;
		}

		if (!qop.empty())
		{
			out += ", cnonce=\"" + cnonce + "\"";
			out += ", qop=" + qop;
			out += ", nc=" + nc;
		}
		// When qop is empty we deliberately emit NO cnonce/qop/nc. See the header:
		// an RFC 2069 server ignores them and computes MD5(HA1:nonce:HA2), so
		// sending them while computing the long form is a silent mismatch.

		if (!ch.opaque.empty())
		{
			out += ", opaque=\"" + ch.opaque + "\"";
		}

		return true;
	}
	// =====================================================================
	// ALLOCATION-FREE CLIENT (UAC) API -- issue #399. See the header.
	//
	// Nothing below may construct a std::string, a std::vector, or anything else
	// that reaches operator new. SipDigestBounded_test pins that with the shared
	// allocation counter; if you add a helper here, keep it on fixed buffers and
	// string_views or that test goes red.
	// =====================================================================

	namespace
	{
		constexpr size_t kHexDigestLen = 32;   // MD5 is 16 bytes -> 32 hex chars

		// Lowercase hex, matching toHex() above byte for byte.
		void hex16(const uint8_t in[16], char (&out)[kHexDigestLen + 1])
		{
			static const char* digits = "0123456789abcdef";
			for (size_t i = 0; i < 16; ++i)
			{
				out[i * 2]     = digits[(in[i] >> 4) & 0x0F];
				out[i * 2 + 1] = digits[in[i] & 0x0F];
			}
			out[kHexDigestLen] = '\0';
		}

		// MD5 over the CONCATENATION of `parts`, without ever concatenating them.
		// Feeding the pieces to one Md5 in order hashes exactly the same byte
		// stream as md5Hex(a + ":" + b + ...) -- that equivalence is the whole
		// basis for this API producing the std::string API's bytes, and
		// SipDigestBounded_test checks it against the RFC vectors.
		//
		// std::initializer_list is a view over a stack array: no allocation.
		void md5HexOf(std::initializer_list<std::string_view> parts,
		              char (&out)[kHexDigestLen + 1])
		{
			Md5 h;
			for (std::string_view p : parts)
			{
				h.update(reinterpret_cast<const uint8_t*>(p.data()), p.size());
			}
			uint8_t digest[16];
			h.finalize(digest);
			hex16(digest, out);
		}

		// Appends into a caller buffer and remembers whether anything failed to
		// fit. Once overflowed it writes nothing further, so a partial value can
		// never be mistaken for a complete one: the caller checks `overflow` once,
		// at the end, and discards the buffer.
		struct BoundedWriter
		{
			char*  buf;
			size_t cap;
			size_t len      = 0;
			bool   overflow = false;

			BoundedWriter(char* b, size_t c) : buf(b), cap(c)
			{
				if (cap == 0) overflow = true;   // no room even for the NUL
				else          buf[0] = '\0';
			}

			void put(std::string_view s)
			{
				if (overflow) return;
				// `>=` not `>`: one byte must stay free for the terminator.
				if (s.size() >= cap - len)
				{
					overflow = true;
					return;
				}
				std::memcpy(buf + len, s.data(), s.size());
				len += s.size();
				buf[len] = '\0';
			}
		};

		// Copy `v` into a fixed field. Refuses (sets `overflow`) rather than
		// truncating -- see the header on why a shortened nonce is worse than no
		// answer at all.
		void storeBounded(char* dst, size_t cap, std::string_view v, bool& overflow)
		{
			if (v.size() >= cap)
			{
				overflow = true;
				return;
			}
			std::memcpy(dst, v.data(), v.size());
			dst[v.size()] = '\0';
		}
	}

	bool parseChallenge(std::string_view challengeHeaderValue,
	                    BoundedChallenge& out,
	                    bool proxyDefault)
	{
		out = BoundedChallenge{};
		out.proxy = proxyDefault;

		bool overflow = false;
		std::string_view matched;
		// The SAME scanner and the SAME key set as the std::string overload, so
		// the two can only differ in where the values are stored.
		const bool isDigest = scanDigestParams(
			challengeHeaderValue, {"www-authenticate", "proxy-authenticate"}, &matched,
			[&out, &overflow](std::string_view k, std::string_view value) {
				if      (iequalsAscii(k, "realm"))     storeBounded(out.realm,     sizeof(out.realm),     value, overflow);
				else if (iequalsAscii(k, "nonce"))     storeBounded(out.nonce,     sizeof(out.nonce),     value, overflow);
				else if (iequalsAscii(k, "opaque"))    storeBounded(out.opaque,    sizeof(out.opaque),    value, overflow);
				else if (iequalsAscii(k, "algorithm")) storeBounded(out.algorithm, sizeof(out.algorithm), value, overflow);
				else if (iequalsAscii(k, "qop"))       storeBounded(out.qopList,   sizeof(out.qopList),   value, overflow);
				else if (iequalsAscii(k, "stale"))     out.stale = iequalsAscii(value, "true");
				// "domain" and unknown parameters are ignored -- see the header.
			});
		if (!isDigest)
		{
			return false;
		}
		if (overflow)
		{
			// Never leave a half-parsed challenge behind for a caller that ignores
			// the return value.
			out = BoundedChallenge{};
			return false;
		}

		if (!matched.empty())
		{
			out.proxy = iequalsAscii(matched, "proxy-authenticate");
		}
		return out.nonce[0] != '\0';
	}

	DigestAlgorithm algorithmOf(const BoundedChallenge& ch)
	{
		const std::string_view alg(ch.algorithm);
		if (alg.empty())                    return DigestAlgorithm::Md5;
		if (iequalsAscii(alg, "md5"))       return DigestAlgorithm::Md5;
		if (iequalsAscii(alg, "md5-sess"))  return DigestAlgorithm::Md5Sess;
		return DigestAlgorithm::Unsupported;
	}

	bool selectQop(const BoundedChallenge& ch, bool& useAuth)
	{
		useAuth = false;
		const std::string_view list(ch.qopList);
		if (list.empty())
		{
			return true;   // no qop at all -> legacy RFC 2069
		}

		// Token walk, NOT list.find("auth"): "auth-int" contains "auth", so a
		// substring test would answer an auth-int-only challenge with qop=auth.
		// Identical walk to the std::string overload.
		size_t i = 0;
		const size_t n = list.size();
		while (i < n)
		{
			while (i < n && (list[i] == ',' ||
			                 std::isspace(static_cast<unsigned char>(list[i])))) ++i;
			size_t start = i;
			while (i < n && list[i] != ',') ++i;
			size_t end = i;
			while (end > start &&
			       std::isspace(static_cast<unsigned char>(list[end - 1]))) --end;
			if (iequalsAscii(list.substr(start, end - start), "auth"))
			{
				useAuth = true;
				return true;
			}
		}
		return false;
	}

	const char* authorizationHeaderName(const BoundedChallenge& ch)
	{
		return ch.proxy ? "Proxy-Authorization" : "Authorization";
	}

	void formatNc(uint32_t count, char (&out)[kNcLen + 1])
	{
		static const char* d = "0123456789abcdef";
		uint32_t v = count;
		for (int i = static_cast<int>(kNcLen) - 1; i >= 0; --i)
		{
			out[i] = d[v & 0xF];
			v >>= 4;
		}
		out[kNcLen] = '\0';
	}

	void makeCnonce(char (&out)[kCnonceLen + 1])
	{
		// Same source and width as the std::string makeCnonce(): 8 CSPRNG bytes.
		uint8_t raw[kCnonceLen / 2];
		fillRandom(raw, sizeof(raw));
		static const char* digits = "0123456789abcdef";
		for (size_t i = 0; i < sizeof(raw); ++i)
		{
			out[i * 2]     = digits[(raw[i] >> 4) & 0x0F];
			out[i * 2 + 1] = digits[raw[i] & 0x0F];
		}
		out[kCnonceLen] = '\0';
	}

	bool buildAuthorization(const BoundedChallenge& ch,
	                        std::string_view username,
	                        std::string_view password,
	                        std::string_view method,
	                        std::string_view uri,
	                        uint32_t ncValue,
	                        std::string_view cnonce,
	                        char* out,
	                        size_t cap,
	                        size_t& outLen)
	{
		// --- Refusal gates: the std::string overload's, in its order. On any of
		// --- these `out` and `outLen` are left untouched, as that overload leaves
		// --- its `out`.
		const std::string_view nonce(ch.nonce);
		if (nonce.empty())
		{
			return false;
		}

		const DigestAlgorithm alg = algorithmOf(ch);
		if (alg == DigestAlgorithm::Unsupported)
		{
			return false;   // RFC 8760 SHA-2: an MD5 answer would simply be wrong
		}

		bool useAuth = false;
		if (!selectQop(ch, useAuth))
		{
			return false;   // auth-int only: we do not hash message bodies
		}

		if (useAuth && cnonce.empty())
		{
			return false;   // qop=auth requires a cnonce (RFC 7616 §3.4)
		}
		if (alg == DigestAlgorithm::Md5Sess && cnonce.empty())
		{
			return false;   // HA1-sess is defined over the cnonce
		}
		if (alg == DigestAlgorithm::Md5Sess && !useAuth)
		{
			return false;   // unverifiable: see the std::string overload's note
		}

		// --- Compute. Every hash is streamed; nothing is concatenated.
		const std::string_view realm(ch.realm);

		char ha1[kHexDigestLen + 1];
		md5HexOf({username, ":", realm, ":", password}, ha1);
		if (alg == DigestAlgorithm::Md5Sess)
		{
			char ha1sess[kHexDigestLen + 1];
			md5HexOf({ha1, ":", nonce, ":", cnonce}, ha1sess);
			std::memcpy(ha1, ha1sess, sizeof(ha1));
		}

		char ha2[kHexDigestLen + 1];
		md5HexOf({method, ":", uri}, ha2);

		char nc[kNcLen + 1];
		formatNc(ncValue, nc);

		char response[kHexDigestLen + 1];
		if (useAuth)
		{
			md5HexOf({ha1, ":", nonce, ":", nc, ":", cnonce, ":", "auth", ":", ha2}, response);
		}
		else
		{
			md5HexOf({ha1, ":", nonce, ":", ha2}, response);
		}

		// --- Emit. Parameter order and quoting are the std::string overload's
		// --- exactly: username/realm/nonce/uri/response/cnonce/opaque quoted,
		// --- algorithm/qop/nc bare (a quoted nc is rejected by Kamailio and
		// --- several SBCs).
		BoundedWriter w(out, cap);
		w.put("Digest username=\""); w.put(username);
		w.put("\", realm=\"");      w.put(realm);
		w.put("\", nonce=\"");      w.put(nonce);
		w.put("\", uri=\"");        w.put(uri);
		w.put("\", response=\"");   w.put(response);
		w.put("\"");

		const std::string_view algorithm(ch.algorithm);
		if (!algorithm.empty())
		{
			w.put(", algorithm="); w.put(algorithm);
		}

		if (useAuth)
		{
			w.put(", cnonce=\""); w.put(cnonce);
			w.put("\", qop=auth, nc="); w.put(nc);
		}

		const std::string_view opaque(ch.opaque);
		if (!opaque.empty())
		{
			w.put(", opaque=\""); w.put(opaque); w.put("\"");
		}

		if (w.overflow)
		{
			// Some bytes may already be in `out`. A truncated Authorization must
			// never be sendable, so leave an empty string rather than a prefix.
			if (cap > 0) out[0] = '\0';
			outLen = 0;
			return false;
		}
		outLen = w.len;
		return true;
	}
}
