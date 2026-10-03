#include "SipMessageBuilder.hpp"

#include <cstdio>

#include "IDGen.hpp"

namespace sipb
{

Err options(Wire& out, const OptionsParams& params)
{
	out.len = 0;

	if (params.targetAor.empty() || params.destIp.empty() || params.localIp.empty())
	{
		return Err::BadField;
	}

	char callIdRand[16]{};
	char branchRand[13]{};
	char fromTagRand[10]{};

	// IDGen, not a local PRNG: these are the identifiers that tell a real
	// in-dialog message from a forged one (#385). Kept at the SSO-sized lengths.
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

	// Cap options ping at kMaxOptionsBytes (640 B, #463): worst-case valid ping
	// is ~450 B, so anything larger is rejected and counted before transmission.
	constexpr size_t kMaxOptionsCap = kMaxOptionsBytes < sizeof(out.bytes)
		? kMaxOptionsBytes
		: sizeof(out.bytes);

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

Err options(Wire& out,
            std::string_view targetAor,
            std::string_view destIp,
            uint16_t destPort,
            std::string_view localIp,
            uint16_t localPort,
            std::string_view fromUser)
{
	OptionsParams p{};
	p.targetAor = targetAor;
	p.destIp = destIp;
	p.destPort = destPort;
	p.localIp = localIp;
	p.localPort = localPort;
	p.fromUser = fromUser;
	return options(out, p);
}

} // namespace sipb
