#include "MulticastPager.hpp"

#include "PoolConfig.hpp"

#if POCKETDIAL_MULTICAST_PAGING

#include <cstring>

#include "RtpSender.hpp"   // buildRtpHeader(): the one RTP header writer

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
#include <unistd.h>
#include <lwip/sockets.h>
#include "esp_random.h"
#define PD_MCAST_SOCKETS 1
#elif defined(__linux__)
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <random>
#define PD_MCAST_SOCKETS 1
#else
#include <random>
#define PD_MCAST_SOCKETS 0
#endif

UdpMcastTx::~UdpMcastTx()
{
#if PD_MCAST_SOCKETS
	if (_sock >= 0) close(_sock);
#endif
}

bool UdpMcastTx::open(uint8_t ttl)
{
#if PD_MCAST_SOCKETS
	if (_sock >= 0) return true;
	const int s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0) return false;
	// One byte: lwIP reads a u8 (LWIP_MULTICAST_TX_OPTIONS, on with LWIP_IGMP=1 in
	// ESP-IDF's lwipopts.h), and Linux accepts a char-sized value too.
	const unsigned char t = ttl;
	if (setsockopt(s, IPPROTO_IP, IP_MULTICAST_TTL, &t, sizeof(t)) != 0)
	{
		close(s);
		return false;
	}
	_sock = s;
	return true;
#else
	(void)ttl;
	return false;
#endif
}

bool UdpMcastTx::sendTo(const uint8_t* data, size_t len, uint32_t groupHost, uint16_t port)
{
#if PD_MCAST_SOCKETS
	if (_sock < 0) return false;
	sockaddr_in to{};
	to.sin_family = AF_INET;
	to.sin_port = htons(port);
	to.sin_addr.s_addr = htonl(groupHost);
	const auto n = sendto(_sock, data, len, 0, reinterpret_cast<const sockaddr*>(&to), sizeof(to));
	return n >= 0 && static_cast<size_t>(n) == len;
#else
	(void)data; (void)len; (void)groupHost; (void)port;
	return false;
#endif
}

size_t MulticastPager::buildPacket(uint8_t* out, size_t cap, bool marker, uint16_t seq,
	uint32_t timestamp, uint32_t ssrc, const uint8_t* payload, size_t payloadLen)
{
	const size_t total = static_cast<size_t>(RtpSender::RTP_HEADER_BYTES) + payloadLen;
	if (!out || total > cap || (payloadLen > 0 && !payload)) return 0;
	RtpSender::buildRtpHeader(out, marker, RtpSender::PAYLOAD_TYPE_PCMU, seq, timestamp, ssrc);
	if (payloadLen > 0) std::memcpy(out + RtpSender::RTP_HEADER_BYTES, payload, payloadLen);
	return total;
}

uint32_t MulticastPager::random32()
{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	return esp_random();
#else
	thread_local std::mt19937 gen{std::random_device{}()};
	thread_local std::uniform_int_distribution<uint32_t> dist;
	return dist(gen);
#endif
}

bool MulticastPager::start(std::string_view callId, uint32_t groupHost, uint16_t port,
	uint32_t ssrc, uint16_t seq0, uint32_t ts0)
{
	if (isActive() || callId.empty() || !_tx || !_tx->open(kTtl)) return false;
	_callId.assign(callId.data(), callId.size());
	_group = groupHost;
	_port = port;
	_ssrc = ssrc;
	_seq = seq0;
	_ts = ts0;
	_first = true;
	_held.store(false, std::memory_order_relaxed);
	_active.store(true, std::memory_order_release);
	return true;
}

bool MulticastPager::stopFor(std::string_view callId)
{
	if (!holds(callId)) return false;
	_active.store(false, std::memory_order_release);
	_callId.clear();
	return true;
}

bool MulticastPager::holds(std::string_view callId) const
{
	return isActive() && !callId.empty() && _callId == callId;
}

void MulticastPager::onRtp(const RtpReceiver::RtpPacket& pkt)
{
	if (!_active.load(std::memory_order_acquire)) return;
	if (_held.load(std::memory_order_acquire)) return;
	_rxPackets.fetch_add(1, std::memory_order_relaxed);
	if (pkt.payloadType != RtpReceiver::PAYLOAD_TYPE_PCMU || pkt.payloadLen == 0) return;

	const size_t n = buildPacket(_pkt, sizeof(_pkt), _first, _seq, _ts, _ssrc,
		pkt.payload, pkt.payloadLen);
	if (n == 0) return;
	_first = false;
	++_seq;
	_ts += static_cast<uint32_t>(pkt.payloadLen);   // G.711: one byte per 8 kHz sample
	if (_tx->sendTo(_pkt, n, _group, _port))
	{
		_txPackets.fetch_add(1, std::memory_order_relaxed);
	}
	else
	{
		_txErrors.fetch_add(1, std::memory_order_relaxed);
	}
}

void MulticastPager::rawSink(void* ctx, const RtpReceiver::RtpPacket& pkt)
{
	if (ctx) static_cast<MulticastPager*>(ctx)->onRtp(pkt);
}

#endif // POCKETDIAL_MULTICAST_PAGING
