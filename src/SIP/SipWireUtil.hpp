#ifndef SIP_WIRE_UTIL_HPP
#define SIP_WIRE_UTIL_HPP

// Shared request-building plumbing for the decomposed SIP state machines
// (ParkOrbit, RegisterBeeper, BlfSubscriptions, ...). Each of them mints raw
// requests by hand and needs the same two pieces: an "ip:port" authority string
// and the minimal held offer. Kept out of SipHeaderUtil.hpp deliberately —
// that header is pure string work and must stay free of socket includes.

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
#include <lwip/sockets.h>
#elif defined(__linux__)
#include <arpa/inet.h>
#elif defined _WIN32 || defined _WIN64
#include <WinSock2.h>
#include <ws2tcpip.h>   // inet_ntop / INET_ADDRSTRLEN live here, not in WinSock2.h
#endif

#include <string>

namespace sipwire
{
	// "a.b.c.d:port" for a v4 peer — the authority the machines stamp into a
	// request-URI and into the Via/Contact host of server-minted requests.
	inline std::string addrToIpPort(const sockaddr_in& addr)
	{
		char ipBuf[INET_ADDRSTRLEN]{};
		inet_ntop(AF_INET, &addr.sin_addr, ipBuf, sizeof(ipBuf));
		return std::string(ipBuf) + ":" + std::to_string(ntohs(addr.sin_port));
	}

	// The top Via of a response, stamped per RFC 3261 §18.2.1 and RFC 3581 §4:
	// `received` is the address the request ACTUALLY arrived from, and a bare
	// `rport` the sender asked for is answered with the source PORT.
	//
	// This used to append ";received=" + the SERVER's own IP, which is not a
	// cosmetic slip. A pjsip-based phone compares `received` against the address
	// in its own Contact, reads the mismatch as NAT, and rewrites its Contact to
	// what we told it — so it advertises <phone-port>@<PBX-ip>. Every subsequent
	// in-dialog request the far end routes through that Contact (re-INVITE for
	// hold/resume, REFER for an attended transfer, BYE) is then addressed to a
	// host:port pair where nothing is listening, and simply retransmits until it
	// times out. On loopback that shows up as a hold that never resumes; on a LAN
	// it is every pjsip phone becoming unreachable mid-call.
	//
	// `via` is the request's top Via verbatim, INCLUDING its "Via:" header name
	// (that is what SipMessage::getVia() returns and setVia() expects back).
	inline std::string viaWithReceived(std::string_view via, const sockaddr_in& src)
	{
		char ipBuf[INET_ADDRSTRLEN]{};
		inet_ntop(AF_INET, &src.sin_addr, ipBuf, sizeof(ipBuf));

		std::string out(via);
		// A bare ";rport" (no value) is the sender asking to be told its source
		// port; give it the real one in place. ";rport=" already carrying a value
		// is left alone — it is not ours to rewrite.
		const size_t rp = out.find(";rport");
		if (rp != std::string::npos)
		{
			const size_t after = rp + 6;   // strlen(";rport")
			const char next = (after < out.size()) ? out[after] : '\0';
			if (next != '=')
			{
				out.insert(after, "=" + std::to_string(ntohs(src.sin_port)));
			}
		}
		out += ";received=";
		out += ipBuf;
		return out;
	}

	// Minimal, well-formed a=inactive offer: the server sources no RTP, so the
	// far end holds the stream. Used by the park hold answer and by the register
	// beep INVITE — they must not drift apart, or a phone that tolerates one
	// would choke on the other.
	inline std::string makeInactiveHoldSdp(const std::string& localIp)
	{
		return
			"v=0\r\n"
			"o=- 0 0 IN IP4 " + localIp + "\r\n"
			"s=pocket-dial\r\n"
			"c=IN IP4 " + localIp + "\r\n"
			"t=0 0\r\n"
			"m=audio 9 RTP/AVP 0\r\n"
			"a=inactive\r\n";
	}
}

#endif
