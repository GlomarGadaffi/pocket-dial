#include "L2RtpFrame.hpp"
#include "EthAccess.hpp"
#include "ArpLookup.hpp"
#include "DmaFramePool.hpp"

#include <cstring>

namespace l2rtp
{
namespace
{
	void put16(uint8_t* out, uint16_t v)
	{
		out[0] = static_cast<uint8_t>((v >> 8) & 0xFF);
		out[1] = static_cast<uint8_t>(v & 0xFF);
	}

	void put32(uint8_t* out, uint32_t v)
	{
		out[0] = static_cast<uint8_t>((v >> 24) & 0xFF);
		out[1] = static_cast<uint8_t>((v >> 16) & 0xFF);
		out[2] = static_cast<uint8_t>((v >> 8) & 0xFF);
		out[3] = static_cast<uint8_t>(v & 0xFF);
	}
}   // namespace

uint16_t ipChecksum(const uint8_t* ipHeader20Bytes)
{
	// RFC 791 §3.1: one's-complement sum of 16-bit words, carries folded
	// back in, then one's-complemented. The caller is responsible for
	// zeroing the checksum field (bytes 10-11) before calling this.
	uint32_t sum = 0;
	for (size_t i = 0; i < kIpHeaderBytes; i += 2)
	{
		sum += (static_cast<uint16_t>(ipHeader20Bytes[i]) << 8) | ipHeader20Bytes[i + 1];
	}
	while (sum >> 16)
	{
		sum = (sum & 0xFFFFu) + (sum >> 16);
	}
	return static_cast<uint16_t>(~sum & 0xFFFFu);
}

void buildTemplate(uint8_t* out, const Endpoint& ep, uint32_t ssrc)
{
	std::memset(out, 0, kHeaderBytes);

	// ── Ethernet (14 bytes) ──────────────────────────────────────────────
	std::memcpy(out + 0, ep.dstMac.data(), 6);
	std::memcpy(out + 6, ep.srcMac.data(), 6);
	put16(out + 12, 0x0800);   // EtherType: IPv4

	// ── IPv4 (20 bytes, no options) ──────────────────────────────────────
	uint8_t* ip = out + kIpOffset;
	ip[0] = 0x45;              // version 4, IHL 5 (20 bytes, no options)
	ip[1] = 0x00;              // DSCP/ECN: best-effort, unmarked
	// bytes 2-3 (total length), 4-5 (identification): placeholders, patchTick() fills them.
	put16(ip + 6, 0x4000);     // flags: Don't Fragment, fragment offset 0
	ip[8] = 64;                // TTL
	ip[9] = 17;                // protocol: UDP
	// bytes 10-11 (header checksum): placeholder, patchTick() fills it.
	put32(ip + 12, ep.srcIp);
	put32(ip + 16, ep.dstIp);

	// ── UDP (8 bytes) ────────────────────────────────────────────────────
	uint8_t* udp = out + kUdpOffset;
	put16(udp + 0, ep.srcPort);
	put16(udp + 2, ep.dstPort);
	// bytes 4-5 (length): placeholder, patchTick() fills it.
	put16(udp + 6, 0x0000);    // checksum: 0 is legal for IPv4 (RFC 768); left unset every tick too

	// ── RTP (12-byte header; SSRC fixed for the stream's life) ──────────
	uint8_t* rtp = out + kRtpOffset;
	rtp[0] = 0x80;             // V=2, P=0, X=0, CC=0 -- never changes, so patchTick() need not touch it
	// byte 1 (M+PT), bytes 2-3 (seq), bytes 4-7 (timestamp): patchTick() fills them every tick.
	put32(rtp + 8, ssrc);
}

size_t patchTick(uint8_t* buf, bool marker, uint8_t payloadType,
	uint16_t seq, uint32_t timestamp,
	const uint8_t* payload, size_t payloadLen,
	uint16_t ipIdent)
{
	if (payloadLen > kMaxRtpDatagramBytes - kRtpHeaderBytes)
	{
		return 0;   // refuse rather than truncate -- see the header's doc comment
	}
	if (payload == nullptr && payloadLen > 0)
	{
		return 0;   // nothing to copy from -- refuse rather than dereference null
	}

	// ── RTP: marker/PT/seq/timestamp change every tick; SSRC and the
	// version byte were fixed once by buildTemplate() and are left alone. ──
	uint8_t* rtp = buf + kRtpOffset;
	rtp[1] = static_cast<uint8_t>((marker ? 0x80 : 0x00) | (payloadType & 0x7F));
	rtp[2] = static_cast<uint8_t>((seq >> 8) & 0xFF);
	rtp[3] = static_cast<uint8_t>(seq & 0xFF);
	rtp[4] = static_cast<uint8_t>((timestamp >> 24) & 0xFF);
	rtp[5] = static_cast<uint8_t>((timestamp >> 16) & 0xFF);
	rtp[6] = static_cast<uint8_t>((timestamp >> 8) & 0xFF);
	rtp[7] = static_cast<uint8_t>(timestamp & 0xFF);
	if (payloadLen > 0)
	{
		std::memcpy(rtp + kRtpHeaderBytes, payload, payloadLen);
	}

	const size_t rtpDatagramLen = kRtpHeaderBytes + payloadLen;
	const size_t udpLen         = kUdpHeaderBytes + rtpDatagramLen;
	const size_t ipTotalLen     = kIpHeaderBytes + udpLen;

	// ── UDP length (checksum stays 0, set once by buildTemplate()) ──────
	put16(buf + kUdpOffset + 4, static_cast<uint16_t>(udpLen));

	// ── IPv4: identification + total length change every tick, so the
	// header checksum must be recomputed every tick too. ────────────────
	uint8_t* ip = buf + kIpOffset;
	put16(ip + 2, static_cast<uint16_t>(ipTotalLen));
	put16(ip + 4, ipIdent);
	ip[10] = 0;
	ip[11] = 0;
	const uint16_t cs = ipChecksum(ip);
	ip[10] = static_cast<uint8_t>((cs >> 8) & 0xFF);
	ip[11] = static_cast<uint8_t>(cs & 0xFF);

	return kHeaderBytes + payloadLen;
}

bool EgressChannel::updateAddressing(const sockaddr_in& dest, uint16_t srcPort, uint32_t ssrc)
{
	uint32_t localIp = 0, localGw = 0, localNetmask = 0;
	if (!EthAccess::getLocalIpInfo(localIp, localGw, localNetmask))
	{
		ready = false;
		return false;
	}

	if (!ready || (++resolveTicks % 250u) == 0u)
	{
		uint32_t destIpHost = ntohl(dest.sin_addr.s_addr);
		uint32_t nextHopHost = resolveNextHop(destIpHost, localIp, localGw, localNetmask);

		sockaddr_in nextHopAddr{};
		nextHopAddr.sin_family = AF_INET;
		nextHopAddr.sin_addr.s_addr = htonl(nextHopHost);

		auto macOpt = ArpLookup::pdLookupMac(nextHopAddr);
		// Gate ready on BOTH ARP lookup AND getLocalMac HAL return (Review point 2)
		if (macOpt.has_value() && EthAccess::getLocalMac(ep.srcMac))
		{
			ep.dstMac = *macOpt;
			ep.srcIp = localIp;
			ep.dstIp = destIpHost;
			ep.srcPort = srcPort;
			ep.dstPort = ntohs(dest.sin_port);

			buildTemplate(hdrTemplate.data(), ep, ssrc);
			ready = true;
		}
		else
		{
			ready = false;
		}
	}

	return ready;
}

bool EgressChannel::transmit(bool marker, uint8_t payloadType, uint16_t seq, uint32_t timestamp,
                             const uint8_t* payload, size_t payloadLen)
{
	if (!ready)
	{
		return false;
	}

	auto frame = DmaFramePool::acquire();
	if (!frame)
	{
		return false;  // Pool exhausted -> fallback to socket
	}

	std::memcpy(frame.data(), hdrTemplate.data(), kHeaderBytes);
	size_t len = patchTick(frame.data(), marker, payloadType,
	                       seq, timestamp, payload, payloadLen, ipIdent++);
	if (len == 0)
	{
		return false;
	}

	return EthAccess::transmitL2(frame.data(), len);
}

}   // namespace l2rtp
