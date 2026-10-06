#ifndef MULTICAST_PAGER_HPP
#define MULTICAST_PAGER_HPP

// MulticastPager: the media half of multicast paging (issue #800, dial 997).
//
// The PBX answers the caller itself (RequestsHandler::onMulticastPageInvite) and
// receives the caller's RTP on one boot-time RtpReceiver whose raw sink is this
// class. Every PCMU frame is re-sent, payload untouched, as RTP to one IPv4
// multicast group with TTL 1, under this page's own SSRC, sequence and
// timestamp (RFC 3550 §5.1). Phones that listen on the group play it with no
// SIP dialog of their own.
//
// Threads: start()/stopFor()/holds() run on the SIP thread under RequestsHandler's
// _mutex. onRtp() runs on the receiver's task. The stream state (group, SSRC,
// sequence, timestamp) is written by start() BEFORE the receiver is started and
// before _active is published, and is touched only by onRtp() afterwards.
//
// #284: onRtp() allocates nothing. The packet is built in a fixed member buffer
// and handed to the McastTx seam. The tx socket is opened once and kept, so
// stopFor() never closes an fd a late onRtp() on the receive task could still be
// sending on (RtpReceiver::stop() returns before its task exits on ESP).

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "RtpReceiver.hpp"

// The send seam. One UDP socket with IP_MULTICAST_TTL set; tests substitute a fake.
class McastTx
{
public:
	virtual ~McastTx() = default;
	// Open the socket (once) and set its multicast TTL. True if it is open.
	virtual bool open(uint8_t ttl) = 0;
	// One datagram to group:port, both in host byte order. Called on the RTP task.
	virtual bool sendTo(const uint8_t* data, size_t len, uint32_t groupHost, uint16_t port) = 0;
};

// BSD sockets: lwIP on ESP, POSIX on a Linux host. On the ESP eth build this goes
// through lwIP, not the L2 RTP bypass the other media paths use, and has no
// board proof yet (#800).
class UdpMcastTx final : public McastTx
{
public:
	UdpMcastTx() = default;
	UdpMcastTx(const UdpMcastTx&) = delete;
	UdpMcastTx& operator=(const UdpMcastTx&) = delete;
	~UdpMcastTx() override;
	bool open(uint8_t ttl) override;
	bool sendTo(const uint8_t* data, size_t len, uint32_t groupHost, uint16_t port) override;

private:
	int _sock = -1;
};

class MulticastPager
{
public:
	static constexpr uint8_t kTtl = 1;
	static constexpr size_t kMaxPayload =
		static_cast<size_t>(RtpReceiver::MAX_DATAGRAM_BYTES - RtpReceiver::RTP_HEADER_BYTES);

	// RTP header (V=2, no CSRC/extension, PT 0) + payload into `out`. Returns the
	// datagram length, or 0 if it does not fit `cap`.
	static size_t buildPacket(uint8_t* out, size_t cap, bool marker, uint16_t seq,
		uint32_t timestamp, uint32_t ssrc, const uint8_t* payload, size_t payloadLen);

	// A fresh 32-bit random value (SSRC and the initial sequence/timestamp, RFC 3550 §5.1).
	static uint32_t random32();

	explicit MulticastPager(McastTx& tx) : _tx(&tx) {}
	MulticastPager(const MulticastPager&) = delete;
	MulticastPager& operator=(const MulticastPager&) = delete;

	void setTxForTest(McastTx* tx) { _tx = tx; }

	// SIP thread. Opens the tx socket if needed, then arms the page for `callId`.
	// False (nothing armed) if a page is already live or the socket cannot be opened.
	bool start(std::string_view callId, uint32_t groupHost, uint16_t port,
		uint32_t ssrc, uint16_t seq0, uint32_t ts0);
	// SIP thread. Disarms the page if `callId` owns it. True if it did.
	bool stopFor(std::string_view callId);
	bool holds(std::string_view callId) const;
	bool isActive() const { return _active.load(std::memory_order_acquire); }
	const std::string& callId() const { return _callId; }

	// SIP thread (#909). A caller that holds the page (sendonly/inactive re-INVITE)
	// is paused: nothing it still sends, such as hold music, goes to the group, and it
	// does not count as liveness, so a hold longer than the silence window ends the
	// page as before. start() clears it.
	void setHeld(bool held) { _held.store(held, std::memory_order_release); }
	bool isHeld() const { return _held.load(std::memory_order_acquire); }

	// RTP task. Every well-formed packet counts as liveness; only PCMU is sent.
	void onRtp(const RtpReceiver::RtpPacket& pkt);
	// RtpReceiver::RawSink shape; ctx is the MulticastPager.
	static void rawSink(void* ctx, const RtpReceiver::RtpPacket& pkt);

	uint32_t rxPackets() const { return _rxPackets.load(std::memory_order_relaxed); }
	uint32_t txPackets() const { return _txPackets.load(std::memory_order_relaxed); }
	uint32_t txErrors() const { return _txErrors.load(std::memory_order_relaxed); }

private:
	McastTx* _tx;
	std::atomic<bool> _active{false};
	std::atomic<bool> _held{false};
	std::string _callId;   // SIP thread only

	// Written by start() before _active is published, then owned by onRtp().
	uint32_t _group = 0;
	uint16_t _port = 0;
	uint32_t _ssrc = 0;
	uint16_t _seq = 0;
	uint32_t _ts = 0;
	bool _first = true;
	uint8_t _pkt[RtpReceiver::MAX_DATAGRAM_BYTES] = {};

	std::atomic<uint32_t> _rxPackets{0};
	std::atomic<uint32_t> _txPackets{0};
	std::atomic<uint32_t> _txErrors{0};
};

#endif // MULTICAST_PAGER_HPP
