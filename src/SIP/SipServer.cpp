#include "SipServer.hpp"
#include "SipMessageTypes.h"

#if defined(ARDUINO)
#include <ESPmDNS.h>
#elif defined(ESP_PLATFORM)
#include <mdns.h>
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

SipServer::SipServer(std::string ip, int port, int httpPort) :
	_socket(ip, port, std::bind(&SipServer::onNewMessage, this, std::placeholders::_1, std::placeholders::_2)),
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
