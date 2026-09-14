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
#include <string_view>

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

	// The same body, but SENDONLY from a real server port: the server transmits
	// (music on hold, issue #162) and ignores anything the far end sends back.
	//
	// Sendonly rather than sendrecv is deliberate. Park is one-way by definition;
	// advertising sendrecv would invite the parked phone to stream audio nothing
	// reads, for the entire duration of the park.
	//
	// PCMU only, matching buildMediaSdp(): every server-terminated leg in this
	// firmware speaks µ-law, and the hold clip is stored as µ-law precisely so the
	// pacing task is a memcpy rather than a transcode.
	inline std::string makeSendonlySdp(const std::string& localIp, int rtpPort)
	{
		return
			"v=0\r\n"
			"o=- 0 0 IN IP4 " + localIp + "\r\n"
			"s=pocket-dial\r\n"
			"c=IN IP4 " + localIp + "\r\n"
			"t=0 0\r\n"
			"m=audio " + std::to_string(rtpPort) + " RTP/AVP 0\r\n"
			"a=rtpmap:0 PCMU/8000\r\n"
			"a=sendonly\r\n";
	}

	// Rewrite every line-anchored direction attribute in an SDP body to
	// a=sendrecv, leaving the rest of the body byte-identical.
	//
	// This exists for one situation: relaying a party's LAST KNOWN SDP into a new
	// leg when that SDP may have been captured while they were on hold. Every
	// phone's Transfer softkey holds the call first and REFERs second, so the
	// media the transferee last negotiated is routinely a=recvonly (or a=inactive
	// / a=sendonly, depending on which side held). Handing that to the transfer
	// target verbatim offers it a one-way stream and the transfer completes with
	// audio missing in one direction — a failure that only shows up on real
	// handsets, never in a signalling trace that "looks right".
	//
	// RFC 3264 §6.1: a fresh offer re-negotiates direction, so overriding the
	// stale attribute is correct, not a lie — the hold is being ended by the very
	// re-INVITE this body rides in. Address/port are NOT touched: a phone that
	// held with the RFC 2543 c=0.0.0.0 form still needs its own re-INVITE to
	// publish a live address, and inventing one here would be a guess.
	inline std::string sdpAsSendrecv(const std::string& sdp)
	{
		static constexpr std::string_view kDirs[] = { "a=sendonly", "a=recvonly", "a=inactive" };
		std::string out = sdp;
		for (const auto dir : kDirs)
		{
			size_t pos = 0;
			while ((pos = out.find(dir, pos)) != std::string::npos)
			{
				// Line-anchored only: "a=sendonly" inside e.g. an a=label value is
				// not a direction attribute, and the trailing check keeps us off a
				// longer token that merely starts the same way.
				const bool atLineStart = (pos == 0) || out[pos - 1] == '\n';
				const size_t after = pos + dir.size();
				const bool atLineEnd = (after >= out.size()) ||
					out[after] == '\r' || out[after] == '\n';
				if (atLineStart && atLineEnd)
				{
					out.replace(pos, dir.size(), "a=sendrecv");
					pos += 10;   // strlen("a=sendrecv")
				}
				else
				{
					pos = after;
				}
			}
		}
		return out;
	}

	// Pull the far end's RTP destination out of an SDP body: the `c=` connection
	// address and the `m=audio` port.
	//
	// Mirrors RequestsHandler::parseCallerRtp's semantics, including its fallback:
	// when `c=` is absent, unparseable, or the unspecified address 0.0.0.0, use the
	// address the SIP message actually arrived from. That fallback is not
	// defensive padding — a phone behind NAT routinely advertises a private `c=`
	// it cannot receive on, and the signalling source is the only address known to
	// work. 0.0.0.0 specifically is the legacy RFC 2543 hold form, which some
	// handsets still send.
	//
	// Returns false when no usable port was found, which the caller must treat as
	// "no audio for this leg" rather than an error.
	inline bool parseRtpTarget(const std::string& sdp, const sockaddr_in& from,
	                           std::string& outIp, uint16_t& outPort)
	{
		outPort = 0;
		outIp.clear();

		// m=audio <port> ...
		size_t m = sdp.find("m=audio ");
		if (m == std::string::npos) return false;
		m += 8;
		int port = 0;
		while (m < sdp.size() && sdp[m] >= '0' && sdp[m] <= '9')
		{
			port = port * 10 + (sdp[m] - '0');
			if (port > 65535) return false;     // malformed; do not wrap into a valid port
			++m;
		}
		// Port 9 is the discard port and 0 means "stream disabled" (RFC 4566 / the
		// a=inactive convention). Neither is somewhere to send audio.
		if (port <= 9) return false;
		outPort = static_cast<uint16_t>(port);

		// c=IN IP4 <addr>
		const size_t c = sdp.find("c=IN IP4 ");
		if (c != std::string::npos)
		{
			const size_t s = c + 9;
			size_t e = s;
			while (e < sdp.size() && sdp[e] != '\r' && sdp[e] != '\n' && sdp[e] != ' ') ++e;
			const std::string addr = sdp.substr(s, e - s);
			if (!addr.empty() && addr != "0.0.0.0") outIp = addr;
		}

		if (outIp.empty())
		{
			char buf[INET_ADDRSTRLEN] = {0};
			if (inet_ntop(AF_INET, &from.sin_addr, buf, sizeof(buf)) != nullptr)
			{
				outIp = buf;
			}
		}
		return !outIp.empty();
	}
}

#endif
