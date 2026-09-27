#ifndef L2_RTP_FRAME_HPP
#define L2_RTP_FRAME_HPP

#include <array>
#include <cstddef>
#include <cstdint>

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
#include <lwip/sockets.h>
#elif defined(__linux__)
#include <netinet/in.h>
#elif defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#endif

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
	// This header does not include RtpReceiver.hpp to check that at compile
	// time (RtpReceiver.hpp has no reason to know about this file, and
	// shouldn't gain one just for this) -- L2RtpFrame_test.cpp includes both
	// and static_asserts the two stay equal, so drift fails the test suite,
	// not silently.
	static constexpr size_t kMaxRtpDatagramBytes = 512;

	static constexpr size_t kIpOffset  = kEthHeaderBytes;
	static constexpr size_t kUdpOffset = kIpOffset + kIpHeaderBytes;
	static constexpr size_t kRtpOffset = kUdpOffset + kUdpHeaderBytes;
	static constexpr size_t kHeaderBytes = kRtpOffset + kRtpHeaderBytes;   // 54

	// Largest possible complete frame: headers + the largest RTP datagram.
	static constexpr size_t kMaxFrameBytes = kHeaderBytes + (kMaxRtpDatagramBytes - kRtpHeaderBytes);

	// ── Buffer placement: THE WHOLE POINT of this file, so it is not a footnote ──
	//
	// buildTemplate()/patchTick() write into a caller-provided buffer. Whether
	// that buffer actually avoids #282's allocation depends ENTIRELY on where
	// the caller puts it:
	//
	//   * a `static` (or global, or heap_caps_malloc'd-once-at-init) buffer in
	//     internal RAM, DMA-capable, aligned -- esp_eth_transmit() takes it
	//     with no bounce, no allocation. This is the only correct choice.
	//   * a task-stack local (`uint8_t buf[kMaxFrameBytes];` inside a function
	//     running on an RTOS task) is WRONG on this codebase specifically:
	//     media task stacks may be PSRAM (PD_TASK_STACK_CAPS /
	//     pd::createTaskPreferPsram, PsramTask.hpp -- rtp_media_rx is, since
	//     #466; rtp_media_tx is kept INTERNAL precisely because the W5500
	//     driver runs on it), so a stack-local buffer can live in PSRAM. The SPI driver
	//     bounces it exactly as it would an lwIP pbuf, and this whole PR
	//     delivers ZERO benefit while looking correct. RtpSender::runLoop's
	//     existing `uint8_t packet[PACKET_BYTES];` is that exact pattern --
	//     do NOT copy it for this buffer.
	//
	// FrameBuffer below is `alignas(4)` (spicommon_dma_setup_priv_buffer checks
	// dma_align_tx_int; 4 is sufficient on this target) so the easy declaration
	// is also the correct one: `static l2rtp::FrameBuffer buf;` per stream slot.
	struct alignas(4) FrameBuffer
	{
		uint8_t bytes[kMaxFrameBytes];
	};

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
	// at least kHeaderBytes long and MUST be placed per the "Buffer placement"
	// note above (a FrameBuffer, not a task-stack local). `ssrc` is written
	// once here (RFC 3550
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
	// payloadLen overflows the datagram cap, or if payload is null while
	// payloadLen is nonzero -- refuse rather than truncate or dereference a
	// null pointer, same discipline as RtpReceiver::sendRaw's
	// MAX_DATAGRAM_BYTES guard. A refused call writes nothing to `buf`.
	size_t patchTick(uint8_t* buf, bool marker, uint8_t payloadType,
		uint16_t seq, uint32_t timestamp,
		const uint8_t* payload, size_t payloadLen,
		uint16_t ipIdent);

	// RFC 791 §3.1 one's-complement checksum over exactly 20 bytes of IPv4
	// header (the checksum field itself must be 0 in `ipHeader20Bytes` when
	// this is called -- patchTick() does that internally; exposed here as
	// its own pure, independently-testable function).
	uint16_t ipChecksum(const uint8_t* ipHeader20Bytes);

	// Resolves the next-hop IPv4 address (host byte order) for a given destination IP.
	// If destIp is on the same subnet as localIp (given netmask), next hop is destIp.
	// Otherwise, next hop is the local default gateway (localGw).
	inline uint32_t resolveNextHop(uint32_t destIp, uint32_t localIp, uint32_t localGw, uint32_t netmask) noexcept
	{
		return ((destIp ^ localIp) & netmask) == 0 ? destIp : localGw;
	}

	// Determines whether an ARP resolution / refresh is needed.
	// Returns true if the channel is not yet ready, or if the 250-tick (~5s) cadence has arrived.
	inline bool shouldResolveArp(bool ready, uint32_t resolveTicks) noexcept
	{
		return !ready || ((resolveTicks % 250u) == 0u);
	}

	// Manages L2 RTP egress state for a single stream (RtpSender or HoldMusic listener).
	// Encapsulates next-hop resolution, periodic ARP/MAC re-resolution, template caching,
	// and DMA buffer acquisition/transmission.
	struct EgressChannel
	{
		Endpoint ep{};
		std::array<uint8_t, kHeaderBytes> hdrTemplate{};
		bool ready = false;
		uint32_t resolveTicks = 0;
		uint16_t ipIdent = 0;

		void reset() noexcept
		{
			ready = false;
			resolveTicks = 0;
			ipIdent = 0;
			ep = Endpoint{};
			hdrTemplate.fill(0);
		}

		// Checks if addressing needs resolution; queries EthAccess and ArpLookup;
		// validates HAL returns (both ARP and getLocalMac); updates template if resolved.
		// Returns true if the channel is ready for L2 transmission.
		bool updateAddressing(const sockaddr_in& dest, uint16_t srcPort, uint32_t ssrc);

		// Borrows a buffer from DmaFramePool, patches the frame with payload,
		// and transmits via EthAccess::transmitL2().
		// Returns true if L2 transmit was successfully queued.
		// Returns false if pool is empty or transmit failed (caller must fallback to socket).
		bool transmit(bool marker, uint8_t payloadType, uint16_t seq, uint32_t timestamp,
		              const uint8_t* payload, size_t payloadLen);
	};
}

#endif // L2_RTP_FRAME_HPP
