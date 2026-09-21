#ifndef PCAP_CAPTURE_HPP
#define PCAP_CAPTURE_HPP

// PcapCapture.hpp — bounded ring buffer of recent SIP signaling packets, and a
// minimal classic libpcap file-format serializer so they can be downloaded and
// opened directly in Wireshark (Issue #33).
//
// RTP/media is deliberately NOT captured here: pocket-dial brokers RTP
// peer-to-peer between phones and never relays it, so there is nothing
// server-side to capture for a call's media — only the SIP signaling that set
// it up, which is also what "SIP Signaling Research" actually wants to inspect.
//
// This is an app-layer capture, not a raw-socket one: pocket-dial has no
// visibility below its own recvfrom()/sendto() calls (no raw sockets, no
// libpcap on ESP32), so each entry is synthesized into a minimal
// Ethernet+IPv4+UDP frame around the exact SIP bytes handled/sent, using dummy
// MACs (the link layer carries no information this server has) and the real
// peer/local IP:port (flipped by capture direction) so Wireshark's SIP
// dissector (triggered by port 5060) decodes it exactly as a real capture
// would. Timestamps are steady-clock-relative, not wall-clock — same basis as
// CallDetailRecord's startMs (see CallDetailRecord.hpp): no RTC is guaranteed
// on the device, so there is no reliable epoch to stamp these with.

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
#include <lwip/sockets.h>
#elif defined(__linux__)
#include <arpa/inet.h>
#elif defined _WIN32 || defined _WIN64
#include <WinSock2.h>
#include <ws2tcpip.h>
#endif

#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "SipWireUtil.hpp"

// Number of recent SIP packets retained for /api/pcap. Each entry costs
// roughly the size of the SIP message it captured (a few hundred bytes to
// ~1.5 KB for an INVITE+SDP) rather than a fixed slot, so — unlike the object
// pools in PoolConfig.hpp — this bounds *count*, not a static footprint.
// Compile-time tunable (-DPOCKETDIAL_PCAP_RING_SIZE=N); lower it to claw back
// RAM on a constrained node.
//
// Issue #101(D): the ring still grows lazily, but it no longer shrinks — once a
// slot has been used its buffer is recycled for the next packet to land there
// rather than freed. So the high-water mark is what a busy node settles at, and
// the steady-state capture path allocates nothing. Capture is unconditional
// (there is no enable flag; see the record() sites in RequestsHandler), which is
// what makes that worth doing rather than a micro-optimization.
// 16, not 64 (#328 follow-up). #278 measured this ring holding **~52 KB of
// internal DRAM at steady state** on .244 at 64 slots, and confirmed that
// shrinking it conserved 91% of the drain -- but it fixed only the override
// plumbing (the documented -D flag had been silently a no-op) and left the
// default at 64, which no build overrides. So the measured, validated fix has
// never been in anything that ships.
//
// A 2026-09-21 heap_trace attribution run found the two single largest
// internal-DRAM call sites on an otherwise idle board are both this ring:
// the inbound capture in RequestsHandler::handle() and the outbound one in
// drainOutbox(). It is not a leak -- it fills and then holds, which is exactly
// why idle free heap settles flat -- but it is a permanent FLOOR under a board
// with roughly 80 KB of internal DRAM to spend, and it is what leaves so little
// headroom that ~12 concurrent HTTP requests (#368) or a few minutes of hold
// music (#328) can take the W5500's DMA bounce buffer with them.
//
// 16 keeps twice the depth of the RING_SIZE=8 treatment #278 actually measured,
// and the plumbing above means a build that genuinely wants 64 can still ask
// for it -- unlike before, that request now takes effect.
#ifndef POCKETDIAL_PCAP_RING_SIZE
#define POCKETDIAL_PCAP_RING_SIZE 16
#endif

class PcapCapture
{
public:
	// Record one SIP message. `outbound` is from the server's own perspective:
	// false for something received from `peer`, true for something sent to
	// `peer`. Not internally synchronized — callers capture under whatever lock
	// already guards the call site (RequestsHandler captures under its own
	// _mutex, the same lock guarding everything else a packet touches).
	void record(bool outbound, const sockaddr_in& peer, std::string_view bytes)
	{
		recordInto(outbound, peer).assign(bytes.data(), bytes.size());
	}

	// Issue #101(D): as record(), but hands back the entry's byte buffer for the
	// caller to serialize straight into instead of making it materialize a
	// temporary std::string first. Both capture sites are on the SIP hot path and
	// run under RequestsHandler::_mutex, and capture is unconditional, so that
	// temporary was a malloc/free per packet inside the critical section — on top
	// of the one this class used to do copying it in.
	//
	// The returned buffer is empty but keeps whatever capacity the evicted entry
	// had, so once the ring has filled — the steady state — recording a packet
	// allocates nothing at all. The reference is valid until the next
	// recordInto()/record()/clear().
	std::string& recordInto(bool outbound, const sockaddr_in& peer)
	{
		Entry* slot;
		if (_entries.size() < POCKETDIAL_PCAP_RING_SIZE)
		{
			// Still filling: grow by one. The ring is deliberately grown lazily
			// rather than reserved up front, so a node that never sees traffic
			// never pays for slots it has not used (see the sizing note above).
			_entries.emplace_back();
			slot = &_entries.back();
		}
		else
		{
			// Full: overwrite the oldest entry in place and advance the ring head.
			// No pop/push, so nothing is freed and nothing is allocated.
			slot = &_entries[_head];
			_head = (_head + 1) % _entries.size();
		}
		slot->seq      = _nextSeq++;
		slot->outbound = outbound;
		slot->peer     = peer;
		slot->tsUs     = monotonicUs();
		slot->bytes.clear();   // clear() keeps capacity; assign()/append() reuse it
		return slot->bytes;
	}

	std::size_t size() const { return _entries.size(); }
	void clear()
	{
		_entries.clear();
		_head = 0;
	}

	// Issue #32: current ring contents formatted for the dashboard's live SIP
	// tracer, which polls GET /api/trace and appends whatever it hasn't already
	// shown (`seq` is monotonic and never reused, so the client can track a
	// high-water mark instead of the server tracking per-client state).
	// cppcheck flags the scalar members below (uninitMemberVarNoCtor). False
	// positive: TraceRecord is a plain aggregate, and its one construction
	// site (traceRecords() below) always brace-initialises every field.
	struct TraceRecord
	{
		// cppcheck-suppress uninitMemberVarNoCtor
		uint64_t    seq;
		// cppcheck-suppress uninitMemberVarNoCtor
		uint64_t    tsUs;
		// cppcheck-suppress uninitMemberVarNoCtor
		bool        outbound;
		std::string peer;   // "ip:port", via sipwire::addrToIpPort
		std::string text;
	};
	std::vector<TraceRecord> traceRecords() const
	{
		std::vector<TraceRecord> out;
		out.reserve(_entries.size());
		forEachOldestFirst([&out](const Entry& e) {
			out.push_back(TraceRecord{e.seq, e.tsUs, e.outbound,
				sipwire::addrToIpPort(e.peer), e.bytes});
		});
		return out;
	}

	// Serialize the ring into a classic libpcap file (24-byte global header +
	// one 16-byte record header + synthesized frame per captured packet).
	// `localIp`/`localPort` fill in the server's own side of each frame.
	std::string toPcapFile(const std::string& localIp, uint16_t localPort) const
	{
		std::string out;
		out.reserve(24 + _entries.size() * 128);

		// Global header. LE container (magic 0xa1b2c3d4 written little-endian);
		// LINKTYPE_ETHERNET = 1.
		appendU32LE(out, 0xa1b2c3d4u);
		appendU16LE(out, 2);
		appendU16LE(out, 4);
		appendU32LE(out, 0);       // thiszone
		appendU32LE(out, 0);       // sigfigs
		appendU32LE(out, 65535u);  // snaplen
		appendU32LE(out, 1u);      // LINKTYPE_ETHERNET

		const uint32_t localAddr = static_cast<uint32_t>(inet_addr(localIp.c_str()));

		forEachOldestFirst([&](const Entry& e) {
			std::string frame = frameFor(e, localAddr, localPort);
			const uint32_t sec  = static_cast<uint32_t>(e.tsUs / 1000000ULL);
			const uint32_t usec = static_cast<uint32_t>(e.tsUs % 1000000ULL);
			const uint32_t len  = static_cast<uint32_t>(frame.size());
			appendU32LE(out, sec);
			appendU32LE(out, usec);
			appendU32LE(out, len);   // incl_len
			appendU32LE(out, len);   // orig_len: never truncated, so equal
			out.append(frame);
		});
		return out;
	}

private:
	// cppcheck flags the scalar members below (uninitMemberVarNoCtor). False
	// positive: recordInto() above is Entry's only populator, and every field
	// (seq/outbound/peer/tsUs) is assigned there immediately after the
	// emplace_back()/reuse that default-constructs the slot, before any of
	// them is ever read.
	struct Entry
	{
		// cppcheck-suppress uninitMemberVarNoCtor
		uint64_t    seq;
		// cppcheck-suppress uninitMemberVarNoCtor
		bool        outbound;
		sockaddr_in peer;
		std::string bytes;
		// cppcheck-suppress uninitMemberVarNoCtor
		uint64_t    tsUs;
	};
	// Ring buffer. Grows to POCKETDIAL_PCAP_RING_SIZE and then stops: entries are
	// overwritten in place, so storage order stops matching capture order once it
	// wraps. `_head` is the index of the OLDEST entry (0 while still filling);
	// everything that reads the ring goes through forEachOldestFirst().
	std::vector<Entry> _entries;
	std::size_t _head = 0;
	// Monotonic, never reused (even across evictions) so a client's high-water
	// mark from traceRecords() stays meaningful after older entries roll off.
	uint64_t _nextSeq = 0;

	// Oldest-to-newest traversal. While the ring is still filling `_head` is 0 and
	// this is plain in-order iteration; after it wraps it walks from `_head`.
	template <typename F>
	void forEachOldestFirst(F&& fn) const
	{
		const std::size_t n = _entries.size();
		for (std::size_t i = 0; i < n; ++i)
		{
			fn(_entries[(_head + i) % n]);
		}
	}

	static uint64_t monotonicUs()
	{
		return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
			std::chrono::steady_clock::now().time_since_epoch()).count());
	}

	static void appendU16LE(std::string& out, uint16_t v)
	{
		out.push_back(static_cast<char>(v & 0xFF));
		out.push_back(static_cast<char>((v >> 8) & 0xFF));
	}
	static void appendU32LE(std::string& out, uint32_t v)
	{
		out.push_back(static_cast<char>(v & 0xFF));
		out.push_back(static_cast<char>((v >> 8) & 0xFF));
		out.push_back(static_cast<char>((v >> 16) & 0xFF));
		out.push_back(static_cast<char>((v >> 24) & 0xFF));
	}
	static void appendU16BE(std::string& out, uint16_t v)
	{
		uint16_t n = htons(v);
		out.append(reinterpret_cast<const char*>(&n), 2);
	}
	static void appendU32Raw(std::string& out, uint32_t netOrderValue)
	{
		// Already in network byte order (an in_addr_t straight from a
		// sockaddr_in / inet_addr()) — append verbatim, no host<->network swap.
		out.append(reinterpret_cast<const char*>(&netOrderValue), 4);
	}

	// Standard 16-bit one's-complement checksum over an IPv4 header (RFC 791
	// §3.1), computed with the checksum field itself treated as zero.
	static uint16_t ipChecksum(const uint8_t* data, std::size_t len)
	{
		uint32_t sum = 0;
		std::size_t i = 0;
		for (; i + 1 < len; i += 2)
		{
			sum += (static_cast<uint16_t>(data[i]) << 8) | data[i + 1];
		}
		if (i < len) sum += static_cast<uint16_t>(data[i]) << 8;
		while (sum >> 16) sum = (sum & 0xFFFFu) + (sum >> 16);
		return static_cast<uint16_t>(~sum);
	}

	// Synthesizes one Ethernet+IPv4+UDP frame around a captured entry's raw SIP
	// bytes. `localAddr` is already network-byte-order (from inet_addr()), as is
	// `e.peer.sin_addr.s_addr`; `localPort`/`e.peer.sin_port` are host/network
	// order respectively and get normalized through appendU16BE.
	static std::string frameFor(const Entry& e, uint32_t localAddr, uint16_t localPort)
	{
		std::string frame;
		frame.reserve(14 + 20 + 8 + e.bytes.size());

		// Ethernet (14 bytes): locally-administered dummy MACs — the link layer
		// carries no real information here — then EtherType IPv4.
		static const unsigned char dstMac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
		static const unsigned char srcMac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};
		frame.append(reinterpret_cast<const char*>(dstMac), 6);
		frame.append(reinterpret_cast<const char*>(srcMac), 6);
		appendU16BE(frame, 0x0800);

		const uint32_t srcIp = e.outbound ? localAddr : e.peer.sin_addr.s_addr;
		const uint32_t dstIp = e.outbound ? e.peer.sin_addr.s_addr : localAddr;
		const uint16_t srcPort = e.outbound ? localPort : ntohs(e.peer.sin_port);
		const uint16_t dstPort = e.outbound ? ntohs(e.peer.sin_port) : localPort;

		const uint16_t udpLen     = static_cast<uint16_t>(8 + e.bytes.size());
		const uint16_t ipTotalLen = static_cast<uint16_t>(20 + udpLen);

		// IPv4 header (20 bytes, no options).
		const std::size_t ipHdrStart = frame.size();
		frame.push_back(static_cast<char>(0x45));  // version 4, IHL 5 (x4 = 20 bytes)
		frame.push_back(static_cast<char>(0x00));  // DSCP/ECN
		appendU16BE(frame, ipTotalLen);
		appendU16BE(frame, 0);       // identification
		appendU16BE(frame, 0x4000);  // flags=DF, fragment offset 0
		frame.push_back(static_cast<char>(64));    // TTL
		frame.push_back(static_cast<char>(17));    // protocol = UDP
		appendU16BE(frame, 0);       // checksum placeholder, patched below
		appendU32Raw(frame, srcIp);
		appendU32Raw(frame, dstIp);

		const uint16_t csum = ipChecksum(
			reinterpret_cast<const uint8_t*>(frame.data() + ipHdrStart), 20);
		frame[ipHdrStart + 10] = static_cast<char>((csum >> 8) & 0xFF);
		frame[ipHdrStart + 11] = static_cast<char>(csum & 0xFF);

		// UDP header (8 bytes) + payload. Checksum 0 = "not computed", valid for
		// IPv4/UDP (RFC 768) and simpler than summing the SIP payload for a
		// value Wireshark doesn't need to re-verify this capture.
		appendU16BE(frame, srcPort);
		appendU16BE(frame, dstPort);
		appendU16BE(frame, udpLen);
		appendU16BE(frame, 0);
		frame.append(e.bytes);

		return frame;
	}
};

#endif
