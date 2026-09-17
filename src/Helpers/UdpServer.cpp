#include "UdpServer.hpp"
#include <thread>
#include <cstring>

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
#include "esp_log.h"
#include "esp_task_wdt.h"   // Issue #235: udp_receiver_task TWDT subscription
static const char* UDP_TAG = "UdpServer";
#endif

// Issue #49: RequestsHandler::handle() runs inline in udp_receiver_task, so this
// task IS the SIP signaling control plane and must share a core with the rest of
// the SIP engine. The SoftAP (esp_main.cpp) and Ethernet (esp_main_eth.cpp) builds
// run the SIP engine task on Core 1 and reserve Core 0 for the HTTP/Wi-Fi/lwIP
// stack, so the receiver defaults to Core 1. The display build (esp_main_display.cpp)
// reserves Core 1 exclusively for the LVGL graphics task and runs SIP on Core 0, so
// it overrides this to 0 via -DPOCKETDIAL_UDP_RX_CORE=0 (see main/CMakeLists.txt).
#ifndef POCKETDIAL_UDP_RX_CORE
#define POCKETDIAL_UDP_RX_CORE 1
#endif

// ── openSocket ────────────────────────────────────────────────────────────────
// On ESP: retries indefinitely with exponential back-off (500 ms → 30 s cap).
// Never throws, never calls esp_restart() — the caller can spin safely.
// On other platforms: throws std::runtime_error on the first failure (original
// behaviour preserved for host/desktop builds).
bool UdpServer::openSocket()
{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	uint32_t backoffMs = kBackoffInitialMs;

	while (true)
	{
		// Close any previously-opened (failed) socket before retrying.
		if (_sockfd >= 0)
		{
			close(_sockfd);
			_sockfd = -1;
		}

		_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
		if (_sockfd < 0)
		{
			ESP_LOGE(UDP_TAG, "socket() failed (errno %d) — retrying in %u ms", errno, backoffMs);
			vTaskDelay(pdMS_TO_TICKS(backoffMs));
			backoffMs = (backoffMs * 2 > kBackoffMaxMs) ? kBackoffMaxMs : backoffMs * 2;
			continue;
		}

		// Receive timeout so receiveLoop() isn't stuck forever when we shut down.
		struct timeval tv;
		tv.tv_sec  = 0;
		tv.tv_usec = 500000; // 500 ms
		setsockopt(_sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

		_servaddr = {};
		_servaddr.sin_family      = AF_INET;
		_servaddr.sin_addr.s_addr = inet_addr(_ip.c_str());
		_servaddr.sin_port        = htons(_port);

		if (bind(_sockfd, reinterpret_cast<const struct sockaddr*>(&_servaddr), sizeof(_servaddr)) < 0)
		{
			ESP_LOGE(UDP_TAG, "bind() failed on %s:%d (errno %d) — retrying in %u ms",
			         _ip.c_str(), _port, errno, backoffMs);
			close(_sockfd);
			_sockfd = -1;
			vTaskDelay(pdMS_TO_TICKS(backoffMs));
			backoffMs = (backoffMs * 2 > kBackoffMaxMs) ? kBackoffMaxMs : backoffMs * 2;
			continue;
		}

		ESP_LOGI(UDP_TAG, "UDP socket bound on %s:%d", _ip.c_str(), _port);
		return true;
	}
#else
	// ── Non-ESP (host / Windows / Linux desktop) ──────────────────────────
#if defined _WIN32 || defined _WIN64
	WSADATA wsa;
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
	{
		throw std::runtime_error("WSAStartup Failed");
	}
#endif

	if ((_sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	{
		throw std::runtime_error("socket creation failed");
	}

#if defined _WIN32 || defined _WIN64
	DWORD timeout = 500;
	setsockopt(_sockfd, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
#else
	struct timeval tv;
	tv.tv_sec  = 0;
	tv.tv_usec = 500000;
	setsockopt(_sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif

	_servaddr = {};
	_servaddr.sin_family      = AF_INET;
	_servaddr.sin_addr.s_addr = inet_addr(_ip.c_str());
	_servaddr.sin_port        = htons(_port);

	if (bind(_sockfd, reinterpret_cast<const struct sockaddr*>(&_servaddr), sizeof(_servaddr)) < 0)
	{
		throw std::runtime_error("bind failed");
	}
	return true;
#endif
}

// ── Constructor ───────────────────────────────────────────────────────────────
UdpServer::UdpServer(std::string ip, int port, OnNewMessageEvent event)
    : _ip(std::move(ip)), _port(port), _onNewMessageEvent(event), _keepRunning(false)
{
	// openSocket() handles WSAStartup on Windows and the recv-timeout setsockopt.
	// On ESP it retries with back-off; on desktop it may throw.
	openSocket();
}

UdpServer::~UdpServer()
{
	closeServer();
}

void UdpServer::startReceive()
{
	_keepRunning = true;
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	if (_receiverExited == nullptr)
	{
		_receiverExited = xSemaphoreCreateBinary();
	}
	xTaskCreatePinnedToCore([](void* arg)
		{
			auto* self = static_cast<UdpServer*>(arg);
			self->receiveLoop();
			// Signal closeServer() that the loop has fully exited and no longer
			// touches any UdpServer members before the object is destroyed.
			if (self->_receiverExited != nullptr)
			{
				xSemaphoreGive(self->_receiverExited);
			}
			vTaskDelete(NULL);
		},
		"udp_receiver_task",
		// RequestsHandler::handle() runs inline on this task, so its stack must cover the
		// deepest SIP call chain. The C++ string-heavy message building, the register-beep
		// UAC (INVITE + ACK/BYE construction), and the media (440) SDP path together blew
		// the old 8KB (stack-overflow panic in udp_receiver_task). 16KB gives real headroom
		// (internal RAM is plentiful; ~250KB free heap at boot).
		16384,
		this,
		5,    // Priority
		&_receiverTaskHandle,
		POCKETDIAL_UDP_RX_CORE   // Issue #49: co-locate with the SIP engine (Core 1 by default)
	);
#else
	_receiverThread = std::thread([=]() { receiveLoop(); });
#endif
}

void UdpServer::receiveLoop()
{
	char buffer[BUFFER_SIZE];
	sockaddr_in senderEndPoint;
	senderEndPoint = {};
	int len = sizeof(senderEndPoint);

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	// Issue #235: subscribe to the Task Watchdog, same reasoning as
	// sip_server_task (main/esp_main*.cpp). Unlike the three per-call media
	// tasks (rtp_media_tx/rx, conf_mix_tick), this task is started once from
	// SipServer's constructor and only stops in UdpServer::closeServer() at
	// shutdown/reboot -- never during ordinary operation -- so it subscribes
	// once and is fed forever, matching sip_server_task's own pattern. The
	// unsubscribe below on loop exit is defensive, not load-bearing today: if
	// closeServer() is ever called while the board keeps running, this keeps
	// a clean stop from turning into a delayed spurious panic instead of
	// silently relying on "this path is never taken in practice."
	esp_err_t wdtErr = esp_task_wdt_add(NULL);
	if (wdtErr != ESP_OK)
	{
		ESP_LOGE(UDP_TAG, "esp_task_wdt_add failed (%s) -- udp_receiver_task stalls will go undetected",
			esp_err_to_name(wdtErr));
	}
#endif

	while (_keepRunning)
	{
		senderEndPoint = {};
		int bytesReceived = 0;
#if defined(__linux__) || defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
		bytesReceived = static_cast<int>(recvfrom(_sockfd, buffer, BUFFER_SIZE, 0,
			reinterpret_cast<struct sockaddr*>(&senderEndPoint), reinterpret_cast<socklen_t*>(&len)));
#elif defined _WIN32 || defined _WIN64
		bytesReceived = recvfrom(_sockfd, buffer, BUFFER_SIZE, 0,
			reinterpret_cast<struct sockaddr*>(&senderEndPoint), &len);
#endif
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
		// Fed on every wake -- this socket's 500 ms recv timeout (openSocket())
		// bounds how long a quiet period can go unfed, same reasoning as
		// RtpReceiver's identical comment. Harmless no-op if the subscription
		// above failed.
		if (wdtErr == ESP_OK)
		{
			(void)esp_task_wdt_reset();
		}
#endif
		if (!_keepRunning || bytesReceived <= 0) continue;
		// Issue #81: zero-copy hand-off — a view of the bytes recvfrom() just wrote
		// into this loop's own stack buffer, valid until the next iteration
		// overwrites it. No allocation on the per-packet hot path; every downstream
		// consumer either copies what it needs synchronously or is done with the
		// view before this call returns (see the OnNewMessageEvent comment above).
		_onNewMessageEvent(std::string_view(buffer, static_cast<size_t>(bytesReceived)), senderEndPoint);
	}
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	if (wdtErr == ESP_OK)
	{
		(void)esp_task_wdt_delete(NULL);
	}
#endif
}

int UdpServer::send(const struct sockaddr_in& address, const std::string& buffer)
{
	return sendto(_sockfd, buffer.c_str(), buffer.size(),
		0, reinterpret_cast<const struct sockaddr*>(&address), sizeof(address));
}

void UdpServer::closeServer()
{
	_keepRunning = false;
	if (_sockfd >= 0)
	{
		shutdown(_sockfd, 2);
#if defined(__linux__) || defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
		close(_sockfd);
#elif defined _WIN32 || defined _WIN64
		closesocket(_sockfd);
#endif
		_sockfd = -1;
	}

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	// Block until receiveLoop() has fully exited before returning, so the
	// UdpServer object is not destroyed out from under the running task.
	// Closing the socket above unblocks recvfrom() immediately; the timeout is
	// a backstop in case the task was never started.
	if (_receiverExited != nullptr)
	{
		xSemaphoreTake(_receiverExited, pdMS_TO_TICKS(2000));
		vSemaphoreDelete(_receiverExited);
		_receiverExited = nullptr;
	}
#else
	if (_receiverThread.joinable()) {
		_receiverThread.join();
	}
#endif
}
