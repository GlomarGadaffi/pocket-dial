#ifndef L2_RTP_FRAME_HPP
#define L2_RTP_FRAME_HPP

#include <array>
#include <cstddef>
#include <cstdint>

// L2RtpFrame: a static, reusable Ethernet+IPv4+UDP+RTP frame template for one
// RTP stream, built once at stream start and patched in place every tick.
//
// Why (issue #282): RtpSender/RtpReceiver's sendto() path hands a socket
// buffer to lwIP, which allocates a pbuf; on the eth variants that pbuf then
// crosses to esp_eth_mac_w5500's emac_w5500_transmit(), which puts the frame
// pointer straight into spi_transaction_t.tx_buffer. If that buffer is not
// already internal/DMA-capable/aligned -- which an lwIP pbuf routinely is not
// -- spicommon_dma_setup_priv_buffer() does a per-frame
// heap_caps_aligned_alloc(MALLOC_CAP_DMA|MALLOC_CAP_INTERNAL) plus a memcpy of
// the whole frame, EVERY transmitted packet. That allocation is the exact one
// #273 observed failing first when internal DRAM is short. This file removes
// it from the RTP hot path: build the frame headers once, patch only what
// changes each tick into a static caller-owned buffer, hand the finished
// bytes straight to esp_eth_transmit(). No malloc, no pbuf, no per-frame heap
// anywhere in this file or its caller.
//
// This is a MITIGATION for #273's DRAM-exhaustion symptom, not a fix for the
// leak itself -- see #282 and #273.
//
// Host-testable by design: everything here is pure byte manipulation. No
// ESP-IDF header, no socket header, no lwIP type appears in this file, so it
// builds and is unit-tested identically on the desktop and on-device.
//
// Byte-order convention: every multi-byte field below is a HOST-byte-order
// parameter; this file does the big-endian (network) byte writes internally,
// the same convention RtpSender::buildRtpHeader() already uses for RTP's
// seq/timestamp/ssrc. A caller holding a sockaddr_in must ntohl()/ntohs() its
// sin_addr/sin_port before calling in -- deliberately, so this header never
// needs to include a socket header to know what those types are.
//
// Scope (phase 1 of #282): the primitive only. Nothing in this file starts a
// task, opens a socket, resolves a MAC (see Helpers/ArpLookup.hpp for that,
// already used by Registrar/RequestsHandler), or calls esp_eth_transmit().
// Adoption into RtpSender/HoldMusic/the #260 relay egress is phase 2.
namespace l2rtp
{
	using Mac = std::array<uint8_t, 6>;

	// ── Frame layout: Ethernet(14) | IPv4(20, no options) | UDP(8) | RTP(12 + payload) ──
	static constexpr size_t kEthHeaderBytes = 14;
	static constexpr size_t kIpHeaderBytes  = 20;
	static constexpr size_t kUdpHeaderBytes = 8;
	static constexpr size_t kRtpHeaderBytes = 12;

	// RTP datagram (RTP header + payload) cap. Matches
	// RtpReceiver::MAX_DATAGRAM_BYTES so one template can carry either a
	// plain 160-byte PCMU frame (RtpSender/HoldMusic) or a relayed raw
	// packet up to the same size the receive side already accepts (#260).
	// Keep these two constants equal by inspection; a static_assert can't
	// reach across the two headers without an include cycle (RtpReceiver.hpp
	// does not need to know about this file).
	static constexpr size_t kMaxRtpDatagramBytes = 512;

	static constexpr size_t kIpOffset  = kEthHeaderBytes;
	static constexpr size_t kUdpOffset = kIpOffset + kIpHeaderBytes;
	static constexpr size_t kRtpOffset = kUdpOffset + kUdpHeaderBytes;
	static constexpr size_t kHeaderBytes = kRtpOffset + kRtpHeaderBytes;   // 54

	// Largest possible complete frame: headers + the largest RTP datagram.
	static constexpr size_t kMaxFrameBytes = kHeaderBytes + (kMaxRtpDatagramBytes - kRtpHeaderBytes);

	// One stream's fixed addressing, unchanged for the stream's life.
	struct Endpoint
	{
		Mac      srcMac{};
		Mac      dstMac{};
		uint32_t srcIp   = 0;   // host byte order, e.g. 0xC0A80CF4 for 192.168.12.244
		uint32_t dstIp   = 0;
		uint16_t srcPort = 0;   // host byte order, e.g. 5062
		uint16_t dstPort = 0;
	};

	// Write the fixed Ethernet+IPv4+UDP+RTP portion into `out`, which must be
	// at least kHeaderBytes long. `ssrc` is written once here (RFC 3550
	// §5.1: fixed for the stream's life) and is never touched by
	// patchTick(). The IPv4 total-length/checksum and UDP length fields are
	// placeholders (patchTick() finishes them each tick) -- the buffer this
	// function alone produces is NOT a valid frame to transmit.
	void buildTemplate(uint8_t* out, const Endpoint& ep, uint32_t ssrc);

	// Patch one tick into a buffer buildTemplate() already initialised (or a
	// byte-for-byte copy of one). `buf` must be at least kHeaderBytes +
	// payloadLen long, and payloadLen must be <=
	// kMaxRtpDatagramBytes - kRtpHeaderBytes.
	//
	// Stamps RTP marker/payloadType/seq/timestamp, copies `payload` in,
	// recomputes IPv4 total length + header checksum and UDP length, and
	// writes `ipIdent` into the IPv4 Identification field (the caller's own
	// monotonic counter -- this frame never goes through lwIP, so nothing
	// else assigns IP IDs for it). UDP checksum is left 0, which is legal
	// for IPv4 (RFC 768) and the same choice the AdBlocker L2 precedent
	// makes (ESP32_AdBlocker_Reborn's l2_finish_reply).
	//
	// Returns the total frame length ready for esp_eth_transmit(), or 0 if
	// payloadLen overflows the datagram cap -- refuse rather than truncate,
	// same discipline as RtpReceiver::sendRaw's MAX_DATAGRAM_BYTES guard,
	// because a truncated RTP payload is a corrupt frame, not a smaller one.
	size_t patchTick(uint8_t* buf, bool marker, uint8_t payloadType,
		uint16_t seq, uint32_t timestamp,
		const uint8_t* payload, size_t payloadLen,
		uint16_t ipIdent);

	// RFC 791 §3.1 one's-complement checksum over exactly 20 bytes of IPv4
	// header (the checksum field itself must be 0 in `ipHeader20Bytes` when
	// this is called -- patchTick() does that internally; exposed here as
	// its own pure, independently-testable function).
	uint16_t ipChecksum(const uint8_t* ipHeader20Bytes);
}

#endif // L2_RTP_FRAME_HPP
