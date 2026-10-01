#include "SipServer.hpp"
#include "SipMessageTypes.h"

#include <cerrno>
#include <chrono>
#include <iostream>

#if defined(ARDUINO)
#include <ESPmDNS.h>
#elif defined(ESP_PLATFORM)
#include <mdns.h>
#include "esp_log.h"
#include "esp_netif.h"
#include <unistd.h>
#endif

#if defined(__linux__) && !defined(ESP_PLATFORM)
#include <arpa/inet.h>
#elif defined _WIN32 || defined _WIN64
#include <WS2tcpip.h>
#endif

// Issue #47: mDNS hostname is compile-time configurable so two units on one LAN
// don't both claim "pocketdial.local". Override with -DPOCKETDIAL_HOSTNAME=\"foo\".
// Issue #416: a pcap slot must hold any datagram the parser can be handed, so
// only messages this server built itself can ever be truncated in the capture.
static_assert(PcapCapture::kSlotBytes >= static_cast<std::size_t>(UdpServer::BUFFER_SIZE),
              "POCKETDIAL_PCAP_SLOT_BYTES is smaller than the UDP receive buffer");

#ifndef POCKETDIAL_HOSTNAME
#define POCKETDIAL_HOSTNAME "pocketdial"
#endif

namespace
{
#if defined(ESP_PLATFORM)
	struct NetmaskQuery
	{
		uint32_t ip;
		uint32_t mask;
	};

	bool matchNetif(esp_netif_t* netif, void* ctx)
	{
		auto* q = static_cast<NetmaskQuery*>(ctx);
		esp_netif_ip_info_t info{};
		if (esp_netif_get_ip_info(netif, &info) != ESP_OK || info.ip.addr != q->ip) return false;
		q->mask = info.netmask.addr;
		return true;
	}
#endif

	// Issue #826: the netmask of the interface holding `ip` (network byte
	// order), so PnP answers only its own subnet. 0 (answer nobody) when the
	// interface cannot be found. Off the board, where PnP never runs, a /24.
	uint32_t localNetmask(uint32_t ip)
	{
#if defined(ESP_PLATFORM)
		NetmaskQuery q{ip, 0};
		(void)esp_netif_find_if(&matchNetif, &q);
		return q.mask;
#else
		(void)ip;
		return htonl(0xFFFFFF00U);
#endif
	}

	[[maybe_unused]] uint32_t uptimeSeconds()
	{
		using namespace std::chrono;
		return static_cast<uint32_t>(duration_cast<seconds>(steady_clock::now().time_since_epoch()).count());
	}
}

SipServer::SipServer(std::string ip, int port, int httpPort) :
	_socket(ip, port, std::bind(&SipServer::onNewMessage, this, std::placeholders::_1, std::placeholders::_2),
		[this](UdpServer::Discard what, std::string_view bytes, sockaddr_in src, size_t fullLen, int err) {
			onDiscard(what, bytes, src, fullLen, err);
		}),
	_handler(ip, port, std::bind(&SipServer::onHandled, this, std::placeholders::_1, std::placeholders::_2))
{
	(void)httpPort;
	_socket.startReceive();

	// Issue #826: PnP mode (Off unless the admin turned it on) and the network
	// the responder answers on.
	_handler.pnp().loadMode();
	in_addr local{};
	if (inet_pton(AF_INET, ip.c_str(), &local) == 1) _localIp = local.s_addr;
	_handler.pnp().setNetwork(_localIp, localNetmask(_localIp), static_cast<uint16_t>(port));

	// ── Multicast DNS (mDNS) responder broadcast ─────────────────────
#if defined(ARDUINO)
	if (MDNS.begin(POCKETDIAL_HOSTNAME)) {
		MDNS.addService("sip", "udp", port);
		MDNS.addService("http", "tcp", httpPort);
		std::cout << "[mDNS] Broadcast active: " << POCKETDIAL_HOSTNAME << ".local\n";
	} else {
		std::cerr << "[mDNS] Failed to start responder\n";
	}
#elif defined(ESP_PLATFORM)
	esp_err_t err = mdns_init();
	if (err == ESP_OK) {
		mdns_hostname_set(POCKETDIAL_HOSTNAME);
		mdns_instance_name_set("Pocket Dial SIP Server");
		mdns_service_add(NULL, "_sip", "_udp", port, NULL, 0);
		mdns_service_add(NULL, "_http", "_tcp", httpPort, NULL, 0);
		std::cout << "[mDNS] Broadcast active: " << POCKETDIAL_HOSTNAME << ".local\n";
	} else {
		std::cerr << "[mDNS] Failed to initialize: " << err << "\n";
	}
#endif

	// ── Desktop Background Tick Thread ───────────────────────────────
#if !defined(ESP_PLATFORM) && !defined(ARDUINO)
	_tickRunning = true;
	_tickThread = std::thread(&SipServer::tickLoop, this);
#endif
}

SipServer::~SipServer()
{
#if !defined(ESP_PLATFORM) && !defined(ARDUINO)
	if (_tickRunning)
	{
		_tickRunning = false;
		if (_tickThread.joinable())
		{
			_tickThread.join();
		}
	}
#endif
}

void SipServer::onNewMessage(std::string_view data, sockaddr_in src)
{
	// Issue #105: createMessage() takes `data` by view (Issue #81), so it stays
	// intact here — handle() gets it too, to capture the exact wire bytes
	// instead of re-serializing the parsed message for /api/pcap.
	auto message = _messagesFactory.createMessage(data, src);
	if (message.has_value())
	{
		_handler.handle(std::move(message.value()), data);
	}
	else
	{
		// Issue #443 S1: createMessage() fails only when the message pool is
		// spent (no heap fallback since #409). The datagram is gone -- count it
		// (it never reaches handle(), so packetsDropped cannot see it).
		_handler.noteRxDiscard(DropProbe::Reason::NoPool, src, data, data.size());
	}
}

void SipServer::onDiscard(UdpServer::Discard what, std::string_view bytes, sockaddr_in src,
                          size_t fullLen, int err)
{
	switch (what)
	{
		case UdpServer::Discard::Oversize:
			_handler.noteRxDiscard(DropProbe::Reason::Oversize, src, bytes, fullLen);
			break;
		case UdpServer::Discard::Empty:
			_handler.noteRxDiscard(DropProbe::Reason::Invalid, src, bytes, 0);
			break;
		case UdpServer::Discard::RecvError:
			_handler.noteRecvError(err);
			break;
	}
}

void SipServer::onHandled(const sockaddr_in& dest, std::shared_ptr<SipMessage> message)
{
	// #462: serialise into the one reusable buffer (see _sendBuf). toString(out)
	// clear()s and reserve()s the exact size, which only reallocates when a
	// message is larger than any sent before -- so after warm-up, no allocation.
	std::lock_guard<std::mutex> lock(_sendMutex);
	message->toString(_sendBuf);
	_socket.send(dest, _sendBuf);
}

// ── Issue #826: SIP PnP ──────────────────────────────────────────────────────

void SipServer::sendPnp(const sockaddr_in& dest, std::string_view msg)
{
	if (msg.empty()) return;
	std::lock_guard<std::mutex> lock(_sendMutex);
	if (_socket.sendBytes(dest, msg.data(), msg.size()) < 0)
	{
		std::cerr << "[PnP] send failed\n";
	}
}

#if defined(ESP_PLATFORM)
// Bound to the GROUP address, not 0.0.0.0: lwIP hands a unicast datagram to
// the first unconnected PCB whose local address matches, and a wildcard bind
// made after the main SIP socket could take its traffic. Only datagrams sent
// to 224.0.1.75 match this one. Replies go out through the main socket, whose
// address is a valid source.
bool SipServer::openPnpSocket(uint32_t now)
{
	if (now < _pnpRetryAt) return false;
	_pnpRetryAt = now + kPnpRetrySeconds;
	const int s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0)
	{
		ESP_LOGW("PnP", "socket() failed (errno %d)", errno);
		return false;
	}
	int one = 1;
	sockaddr_in group{};
	group.sin_family = AF_INET;
	group.sin_port = htons(pnp::kPort);
	bool ok = setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == 0;
	ok = ok && inet_pton(AF_INET, pnp::kGroup, &group.sin_addr) == 1;
	ok = ok && bind(s, reinterpret_cast<const sockaddr*>(&group), sizeof(group)) == 0;
	ip_mreq mreq{};
	mreq.imr_multiaddr = group.sin_addr;
	mreq.imr_interface.s_addr = _localIp;
	ok = ok && setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) == 0;
	if (!ok)
	{
		ESP_LOGW("PnP", "cannot join %s:%u (errno %d); retrying in %u s",
			pnp::kGroup, static_cast<unsigned>(pnp::kPort), errno, static_cast<unsigned>(kPnpRetrySeconds));
		close(s);
		return false;
	}
	_pnpSock = s;
	ESP_LOGI("PnP", "listening on %s:%u", pnp::kGroup, static_cast<unsigned>(pnp::kPort));
	return true;
}

void SipServer::closePnpSocket()
{
	if (_pnpSock < 0) return;
	close(_pnpSock);   // also leaves the group
	_pnpSock = -1;
	_pnpRetryAt = 0;
}

void SipServer::pollPnp()
{
	PnpResponder& pnp = _handler.pnp();
	if (pnp.mode() == PnpResponder::Mode::Off)
	{
		closePnpSocket();
		return;
	}
	const uint32_t now = uptimeSeconds();
	if (_pnpSock < 0 && !openPnpSocket(now)) return;
	auto canServe = [this](std::string_view mac) { return _handler.canProvisionMac(mac); };
	for (int i = 0; i < kPnpDrainPerPoll; ++i)
	{
		sockaddr_in src{};
		socklen_t len = sizeof(src);
		const int n = recvfrom(_pnpSock, _pnpRx.data(), _pnpRx.size(), MSG_DONTWAIT,
			reinterpret_cast<sockaddr*>(&src), &len);
		if (n <= 0) break;   // EWOULDBLOCK: drained
		const PnpResponder::Reply r = pnp.onDatagram(
			std::string_view(_pnpRx.data(), static_cast<size_t>(n)), src, now, canServe);
		sendPnp(src, r.ok);
		sendPnp(src, r.notify);
	}
}
#else
bool SipServer::openPnpSocket(uint32_t) { return false; }
void SipServer::closePnpSocket() {}
void SipServer::pollPnp() {}
#endif

#if !defined(ESP_PLATFORM) && !defined(ARDUINO)
void SipServer::tickLoop()
{
	while (_tickRunning)
	{
		_handler.tick();
		std::this_thread::sleep_for(std::chrono::milliseconds(500));
	}
}
#endif
