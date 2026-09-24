#include "SipServer.hpp"
#include "SipMessageTypes.h"

#if defined(ARDUINO)
#include <ESPmDNS.h>
#elif defined(ESP_PLATFORM)
#include <mdns.h>
#endif

// Issue #47: mDNS hostname is compile-time configurable so two units on one LAN
// don't both claim "pocketdial.local". Override with -DPOCKETDIAL_HOSTNAME=\"foo\".
#ifndef POCKETDIAL_HOSTNAME
#define POCKETDIAL_HOSTNAME "pocketdial"
#endif

SipServer::SipServer(std::string ip, int port, int httpPort) :
	_socket(ip, port, std::bind(&SipServer::onNewMessage, this, std::placeholders::_1, std::placeholders::_2),
		[this](UdpServer::Discard what, std::string_view bytes, sockaddr_in src, size_t fullLen, int err) {
			onDiscard(what, bytes, src, fullLen, err);
		}),
	_handler(ip, port, std::bind(&SipServer::onHandled, this, std::placeholders::_1, std::placeholders::_2))
{
	(void)httpPort;
	_socket.startReceive();

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
		// Issue #443 S1: createMessage() fails only when the message pool and
		// its bounded heap fallback are spent. The datagram is gone -- count it
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
	_socket.send(dest, message->toString());
}

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
