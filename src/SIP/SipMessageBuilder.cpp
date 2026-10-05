#include "SipMessageBuilder.hpp"

#include <cstdio>
#include <cstring>

#include "IDGen.hpp"
#include "SipHeaderUtil.hpp"

namespace sipb
{

namespace
{

// A Request-URI, host or Call-ID: printable ASCII with no space (RFC 3261 §25.1).
bool isToken(std::string_view v)
{
	if (v.empty()) return false;
	for (const char ch : v)
	{
		const unsigned char c = static_cast<unsigned char>(ch);
		if (c <= ' ' || c >= 0x7f) return false;
	}
	return true;
}

// A From or To value: a quoted display name may carry SP, HTAB and UTF-8, but a
// CR or LF would end the header and start one the phone never sent.
bool isHeaderText(std::string_view v)
{
	if (v.empty()) return false;
	for (const char ch : v)
	{
		const unsigned char c = static_cast<unsigned char>(ch);
		if ((c < ' ' && c != '\t') || c == 0x7f) return false;
	}
	return true;
}

// Appends to a fixed buffer, keeping one byte for the NUL. No printf: the BYE is
// also built on the 4 KB http_conn stack (/api/kill), and the stack gate charges
// any *printf 2048 B there.
struct Appender
{
	char* at;
	size_t room;   // bytes left, the NUL's included
	bool full;

	void put(std::string_view s)
	{
		if (full || s.size() >= room)
		{
			full = true;
			return;
		}
		std::memcpy(at, s.data(), s.size());
		at += s.size();
		room -= s.size();
	}

	void putUint(uint32_t v)
	{
		char digits[10];
		size_t i = sizeof(digits);
		do
		{
			digits[--i] = static_cast<char>('0' + v % 10);
			v /= 10;
		} while (v != 0);
		put(std::string_view(digits + i, sizeof(digits) - i));
	}

	// IDGen, not a local PRNG: the branch is what tells a real response to this
	// BYE from a forged one (#385).
	void putRandom(size_t n)
	{
		if (full || n >= room)
		{
			full = true;
			return;
		}
		IDGen::fill(at, n);
		at += n;
		room -= n;
	}
};

} // namespace

Err options(OptionsWire& out, const OptionsParams& params)
{
	out.len = 0;

	if (params.targetAor.empty() || params.destIp.empty() || params.localIp.empty())
	{
		return Err::BadField;
	}
	// Defense in depth: SipClient::setContactUri already refuses these, but a
	// CR, LF, NUL or space in the request line would split or end the message.
	for (const char ch : params.requestUri)
	{
		const unsigned char c = static_cast<unsigned char>(ch);
		if (c <= ' ' || c >= 0x7f) return Err::BadField;
	}

	char callIdRand[16]{};
	char branchRand[13]{};
	char fromTagRand[10]{};

	// IDGen, not a local PRNG: these are the identifiers that tell a real
	// in-dialog message from a forged one (#385). The lengths are the ones the
	// ping had before the builder (#463), so its bytes on the wire are unchanged.
	IDGen::fill(callIdRand, 15);
	IDGen::fill(branchRand, 12);
	IDGen::fill(fromTagRand, 9);

	const int targetLen = static_cast<int>(params.targetAor.size());
	const int destIpLen = static_cast<int>(params.destIp.size());
	const int localIpLen = static_cast<int>(params.localIp.size());
	const int fromUserLen = static_cast<int>(params.fromUser.size());

	// "sip:" + a 64-char AOR + "@" + dotted quad + ":" + port fits in 96.
	char fallbackUri[96]{};
	std::string_view requestUri = params.requestUri;
	if (requestUri.empty())
	{
		const int u = std::snprintf(fallbackUri, sizeof(fallbackUri), "sip:%.*s@%.*s:%u",
			targetLen, params.targetAor.data(), destIpLen, params.destIp.data(), params.destPort);
		if (u <= 0 || static_cast<size_t>(u) >= sizeof(fallbackUri))
		{
			return Err::Truncated;
		}
		requestUri = std::string_view(fallbackUri, static_cast<size_t>(u));
	}
	const int requestUriLen = static_cast<int>(requestUri.size());

	// The buffer is the cap (640 B, #463). A legitimate ping with a 64-char AOR,
	// a dotted-quad local IP and a 128-byte registered Contact is ~490 B.
	constexpr size_t kMaxOptionsCap = sizeof(out.bytes);

	const int n = std::snprintf(out.bytes, kMaxOptionsCap,
		"OPTIONS %.*s SIP/2.0\r\n"
		"Via: SIP/2.0/UDP %.*s:%u;branch=z9hG4bK%s\r\n"
		"To: <sip:%.*s@%.*s:%u>\r\n"
		"From: <sip:%.*s@%.*s:%u>;tag=%s\r\n"
		"Call-ID: %s@%.*s\r\n"
		"CSeq: 1 OPTIONS\r\n"
		"Max-Forwards: 70\r\n"
		"User-Agent: pocket-dial\r\n"
		"Content-Length: 0\r\n\r\n",
		requestUriLen, requestUri.data(),
		localIpLen, params.localIp.data(), params.localPort, branchRand,
		targetLen, params.targetAor.data(), destIpLen, params.destIp.data(), params.destPort,
		fromUserLen, params.fromUser.data(), localIpLen, params.localIp.data(), params.localPort, fromTagRand,
		callIdRand, localIpLen, params.localIp.data());

	if (n <= 0 || static_cast<size_t>(n) >= kMaxOptionsCap)
	{
		out.len = 0;
		return Err::Truncated;
	}

	out.len = static_cast<size_t>(n);
	return Err::Ok;
}

Err bye(ByeWire& out, const ByeParams& params)
{
	out.len = 0;

	// The same stripping main's buildServerBye() did, so a whole header line
	// and a bare value give the same bytes; validated after it.
	const std::string_view from = siphdr::stripHeaderNameView(params.from);
	const std::string_view to = siphdr::stripHeaderNameView(params.to);
	const std::string_view callId = siphdr::stripHeaderNameView(params.callId);
	const bool composed = params.requestUri.empty();
	const bool uriOk = composed ? isToken(params.targetUser) && isToken(params.destIp)
	                            : isToken(params.requestUri);
	if (!uriOk || !isToken(params.localIp) || !isToken(callId) ||
	    !isHeaderText(from) || !isHeaderText(to))
	{
		return Err::BadField;
	}

	Appender w{out.bytes, sizeof(out.bytes), false};
	w.put("BYE ");
	if (composed)
	{
		w.put("sip:");
		w.put(params.targetUser);
		w.put("@");
		w.put(params.destIp);
		w.put(":");
		w.putUint(params.destPort);
	}
	else
	{
		w.put(params.requestUri);
	}
	w.put(" SIP/2.0\r\nVia: SIP/2.0/UDP ");
	w.put(params.localIp);
	w.put(":");
	w.putUint(params.localPort);
	w.put(";branch=z9hG4bK");
	w.putRandom(12);
	w.put("\r\nFrom: ");
	w.put(from);
	w.put("\r\nTo: ");
	w.put(to);
	w.put("\r\nCall-ID: ");
	w.put(callId);
	w.put("\r\nCSeq: ");
	w.putUint(params.cseq);
	w.put(" BYE\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n");
	if (w.full)
	{
		return Err::Truncated;
	}
	*w.at = '\0';
	out.len = sizeof(out.bytes) - w.room;
	return Err::Ok;
}

} // namespace sipb
