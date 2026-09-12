// HttpServer.cpp: Issues #23 and #28 resolved.
#include "HttpServer.hpp"
#include "RequestsHandler.hpp"
#include "DialPlan.hpp"          // Issue #69: dial-rule validation shared with setDialRule
#include "CallDetailRecord.hpp"
#include "AdminAuth.hpp"
#include "DeviceConfig.hpp"
#include "OtaUpdater.hpp"
#include "ProvisioningConfig.hpp"
#include "index_html.h"
#include "IPHelper.hpp"
#include <cstring>
#include <sstream>
#include <iostream>
#include <chrono>
#include <algorithm>
#include <vector>

#if defined(POCKETDIAL_HAS_WIFI)
#include "esp_wifi.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_system.h"
#endif

#if defined(ESP_PLATFORM)
// OTA reboot path needs esp_restart() + a deferred-restart FreeRTOS task. These
// are available on EVERY ESP transport (WiFi, Ethernet, display), not just
// POCKETDIAL_HAS_WIFI, so guard them on the platform rather than the transport.
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#endif

// Forward declarations for the file-local form/URL helpers (defined lower down).
// sendApiDnd() uses getFormParam() but is defined earlier in this TU.
static std::string getFormParam(const std::string& body, const std::string& key);

// Captive-portal decay hold. The display app's decay watchdog reads this; the web
// "/api/configuring" confirm sets it to pause the auto-switch to Standalone while a user is
// actively configuring. Defined here so it links in every transport (the display references
// it via extern; other transports simply never read it).
volatile bool g_decayHold = false;

HttpServer::HttpServer(const std::string& ip, int port, RequestsHandler* handler)
	: _ip(ip), _port(port), _listenSock(-1), _handler(handler), _running(false)
{
	_startTime = currentTimeMs();

#if defined _WIN32 || defined _WIN64
	// WSAStartup may already be called by UdpServer, but calling it again is safe
	WSADATA wsa;
	WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

	// PLAN_ADMIN_HTTP_ONLY.md: dark by default once provisioned. An unprovisioned
	// device must keep today's behavior exactly (listen immediately — onboarding
	// needs the web UI reachable before any admin credential exists). A
	// provisioned device stays dark; acceptLoop()'s per-tick check is what opens
	// it once a live admin-open deadline exists (invariant I1: fail closed).
	if (!AdminAuth::isProvisioned())
	{
		if (!openListenSocket())
		{
			throw std::runtime_error("HttpServer: failed to open listen socket on port " + std::to_string(_port));
		}
	}
}

bool HttpServer::openListenSocket()
{
	if (_listenSock >= 0)
	{
		return true; // already open
	}

	int sock = static_cast<int>(socket(AF_INET, SOCK_STREAM, 0));
	if (sock < 0)
	{
		return false;
	}

	// Allow address reuse
	int opt = 1;
#if defined _WIN32 || defined _WIN64
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt));
#else
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#endif

	sockaddr_in addr{};
	addr.sin_family = AF_INET;
	// Bind to all interfaces (INADDR_ANY) rather than the one configured IP.
	// Binding a listening socket to a specific, dynamically-assigned address is
	// fragile on lwip: in Wi-Fi STATION mode the DHCP-assigned IP is bound here,
	// and connections to it were accepted by lwip into the backlog but never
	// serviced (dashboard unreachable on a LAN, while the SoftAP's static
	// 192.168.4.1 worked). INADDR_ANY serves on every interface/IP and is robust
	// across AP/STA mode switches and IP/lease changes. _ip is still used for
	// display/logging and the captive-portal same-origin check.
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(static_cast<uint16_t>(_port));

	if (bind(sock, reinterpret_cast<const struct sockaddr*>(&addr), sizeof(addr)) < 0)
	{
		closeSocket(sock);
		return false;
	}

	if (listen(sock, 8) < 0)
	{
		closeSocket(sock);
		return false;
	}

	_listenSock = sock;
	return true;
}

void HttpServer::closeListenSocket()
{
	if (_listenSock < 0)
	{
		return; // already closed
	}
	shutdown(_listenSock, 2);
	closeSocket(_listenSock);
	_listenSock = -1;
}

HttpServer::~HttpServer()
{
	_running = false;
	// Close the listen socket to unblock accept()
	closeListenSocket();
	if (_acceptThread.joinable())
	{
		_acceptThread.join();
	}
}

void HttpServer::start()
{
	_running = true;
	_acceptThread = std::thread(&HttpServer::acceptLoop, this);
}

void HttpServer::acceptLoop()
{
	while (_running)
	{
		// PLAN_ADMIN_HTTP_ONLY.md Phase 2: recompute open/closed every tick.
		// Unprovisioned devices always stay open (matches the constructor's
		// initial state). A provisioned device is open only within a live
		// admin-open deadline; ambiguous/missing handler resolves to closed
		// (invariant I1 — fail closed).
		bool shouldBeOpen;
		if (!AdminAuth::isProvisioned())
		{
			shouldBeOpen = true;
		}
		else
		{
			RequestsHandler* handler = _handler.load(std::memory_order_acquire);
			uint64_t deadline = handler ? handler->getAdminHttpOpenUntilMs() : 0;
			shouldBeOpen = (deadline != 0) && (currentTimeMs() < deadline);
		}

		bool currentlyOpen = (_listenSock >= 0);
		if (shouldBeOpen && !currentlyOpen)
		{
			if (openListenSocket())
			{
				std::cerr << "[HttpServer] admin HTTP plane opened\n";
			}
		}
		else if (!shouldBeOpen && currentlyOpen)
		{
			closeListenSocket();
			std::cerr << "[HttpServer] admin HTTP plane closed\n";
		}

		if (_listenSock < 0)
		{
			// Dark: nothing to select() on. Poll at the same ~250ms cadence as
			// the open path so re-provisioning or TTL expiry is observed promptly.
			std::this_thread::sleep_for(std::chrono::milliseconds(250));
			continue;
		}

		fd_set readfds;
		FD_ZERO(&readfds);
		FD_SET(static_cast<unsigned int>(_listenSock), &readfds);

		timeval tv{};
		tv.tv_sec = 0;
		tv.tv_usec = 250000; // 250ms timeout

		int activity = select(_listenSock + 1, &readfds, nullptr, nullptr, &tv);
		if (activity < 0)
		{
			if (!_running) break;
			std::this_thread::sleep_for(std::chrono::milliseconds(100));
			continue;
		}
		if (activity == 0)
		{
			continue; // Timeout, loop and check _running
		}

		sockaddr_in clientAddr{};
#if defined _WIN32 || defined _WIN64
		int addrLen = sizeof(clientAddr);
#else
		socklen_t addrLen = sizeof(clientAddr);
#endif
		int clientSock = static_cast<int>(accept(_listenSock,
			reinterpret_cast<struct sockaddr*>(&clientAddr), &addrLen));

		if (clientSock < 0)
		{
			if (!_running) break;
			continue;
		}

		// Dispatch client handling in a detached thread context to prevent DoS connection stalls.
		// std::thread's constructor THROWS std::system_error if the underlying task can't be
		// created (transient heap/task-limit pressure — e.g. the dashboard polling every 2s
		// while SIP traffic churns the heap). An uncaught throw here runs on the accept-loop
		// pthread and calls std::terminate()/abort(), rebooting the whole device. Catch it and
		// drop just this one connection so the server keeps serving instead of crashing.
		try
		{
			std::thread([this, clientSock]() {
				handleClient(clientSock);
			}).detach();
		}
		catch (const std::exception& e)
		{
			std::cerr << "[HttpServer] connection thread spawn failed: " << e.what()
				<< " — dropping connection\n";
#if defined _WIN32 || defined _WIN64
			closesocket(clientSock);
#else
			close(clientSock);
#endif
			// Brief backoff so we don't spin-fail under sustained memory pressure.
			std::this_thread::sleep_for(std::chrono::milliseconds(20));
		}
	}
}

void HttpServer::handleClient(int clientSock)
{
	// Peer address, for per-client brute-force accounting on /api/admin/login.
	// Best-effort: an empty string falls back to AdminAuth's shared unkeyed
	// bucket, which is the old global behaviour rather than an open door.
	std::string peerIp;
	{
		struct sockaddr_in peer{};
#if defined _WIN32 || defined _WIN64
		int peerLen = static_cast<int>(sizeof(peer));
#else
		socklen_t peerLen = sizeof(peer);
#endif
		if (getpeername(clientSock, reinterpret_cast<struct sockaddr*>(&peer), &peerLen) == 0)
		{
			char ipbuf[INET_ADDRSTRLEN] = {0};
			if (inet_ntop(AF_INET, &peer.sin_addr, ipbuf, sizeof(ipbuf)) != nullptr)
			{
				peerIp = ipbuf;
			}
		}
	}

	// Issue #23 resolved: Added SO_RCVTIMEO per-client socket timeout and capped Content-Length to 16KB to prevent Accept thread DoS
#if defined _WIN32 || defined _WIN64
	DWORD tv = 5000; // 5 seconds timeout
	setsockopt(clientSock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
#else
	struct timeval tv{ .tv_sec = 5, .tv_usec = 0 };
	setsockopt(clientSock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif

	// Heap-allocate the read buffer. On ESP32 each connection runs on a detached
	// std::thread, i.e. an IDF pthread; sdkconfig.defaults sets
	// CONFIG_PTHREAD_TASK_STACK_SIZE_DEFAULT=8192, so a 4 KB stack-local buffer
	// would consume half the stack before any handler ran. Using std::vector keeps
	// the data on the heap. (This comment previously claimed a ~3 KB stack, which
	// has not matched sdkconfig for some time.)
	std::vector<char> buf(4096, 0);

	// Read initial data. A follow-up loop below handles POST bodies that span
	// multiple TCP segments (see Content-Length body-read completion below).
#if defined _WIN32 || defined _WIN64
	int bytesRead = recv(clientSock, buf.data(), static_cast<int>(buf.size()) - 1, 0);
#else
	int bytesRead = static_cast<int>(recv(clientSock, buf.data(), buf.size() - 1, 0));
#endif

	if (bytesRead <= 0)
	{
		closeSocket(clientSock);
		return;
	}

	// #18: ensure the complete POST body is present before parsing.
	// If the headers indicate a Content-Length larger than what arrived in the
	// first segment, keep reading until we have it all.
	std::string raw(buf.data(), static_cast<size_t>(bytesRead));

	// --- OTA upload interception (firmware streaming) -------------------------
	// A firmware image is >1.5 MB, so it must NOT flow through the 16 KB-capped
	// buffered path below. As soon as we have the request line + full header
	// block in the first recv, detect "POST /api/ota/upload" and hand off to the
	// streaming handler, which drains the body in fixed chunks. We require the
	// header terminator (\r\n\r\n) to be present in this first segment — it is
	// for any real HTTP client (headers are a few hundred bytes, the 4 KB recv
	// covers them; the multi-MB part is the body, which we stream).
	{
		size_t reqLineEnd = raw.find("\r\n");
		size_t hdrEnd     = raw.find("\r\n\r\n");
		if (reqLineEnd != std::string::npos && hdrEnd != std::string::npos)
		{
			// Cheap method+path probe on the request line only.
			const std::string reqLine = raw.substr(0, reqLineEnd);
			if (reqLine.compare(0, 5, "POST ") == 0 &&
			    reqLine.find(" /api/ota/upload ") != std::string::npos)
			{
				// Parse just the header block (parseRequest tolerates a truncated
				// body) to get method/path/origin/host/cookie for the auth gate.
				HttpRequest otaReq = parseRequest(raw.substr(0, hdrEnd + 4));
				otaReq.clientIp = peerIp;

				// Same gate as every other mutating endpoint. Flashing firmware is
				// the most consequential thing this server does, so it gets the CSRF
				// check too — the dashboard's upload path sends the token.
				if (!requireAdmin(clientSock, otaReq, true))
				{
					closeSocket(clientSock);
					return;
				}

				// Parse Content-Length WITHOUT the 16 KB cap (firmware is large).
				size_t otaLen = 0;
				size_t cl = raw.find("Content-Length:");
				if (cl == std::string::npos) cl = raw.find("content-length:");
				if (cl != std::string::npos && cl < hdrEnd)
				{
					size_t p = cl + 15;
					while (p < hdrEnd && std::isspace(static_cast<unsigned char>(raw[p]))) ++p;
					while (p < hdrEnd && std::isdigit(static_cast<unsigned char>(raw[p])))
					{
						// Clamp to a sane ceiling (32 MB > 16 MB flash) to bound work.
						if (otaLen > 32u * 1024u * 1024u) { otaLen = 32u * 1024u * 1024u; break; }
						otaLen = otaLen * 10 + static_cast<size_t>(raw[p] - '0');
						++p;
					}
				}
				if (otaLen == 0)
				{
					sendResponse(clientSock, 411, "Length Required", "application/json",
					             "{\"error\":\"OTA upload requires a non-zero Content-Length\"}");
					closeSocket(clientSock);
					return;
				}

				handleOtaUpload(clientSock, raw, hdrEnd + 4, otaLen);
				closeSocket(clientSock);
				return;
			}
		}
	}
	// --- end OTA interception -------------------------------------------------

	size_t clPos = raw.find("Content-Length:");
	if (clPos == std::string::npos)
		clPos = raw.find("content-length:");
	if (clPos != std::string::npos)
	{
		size_t valStart = raw.find_first_not_of(" \t", clPos + 15);
		size_t valEnd   = raw.find_first_of("\r\n", valStart);
		if (valStart != std::string::npos && valEnd != std::string::npos)
		{
			size_t contentLength = 0;
			size_t parseIdx = valStart;
			while (parseIdx < valEnd && std::isspace(static_cast<unsigned char>(raw[parseIdx]))) ++parseIdx;
			while (parseIdx < valEnd && std::isdigit(static_cast<unsigned char>(raw[parseIdx])))
			{
				if (contentLength > 200000000)
				{
					contentLength = 200000000;
					break;
				}
				contentLength = contentLength * 10 + (raw[parseIdx] - '0');
				++parseIdx;
			}

			// Cap total body we are willing to read (16 KB is generous for wifi passwords)
			constexpr size_t MAX_BODY_BYTES = 16384;
			if (contentLength > MAX_BODY_BYTES)
			{
				sendResponse(clientSock, 413, "Payload Too Large", "application/json",
				             "{\"error\":\"request body exceeds 16 KB limit\"}");
				closeSocket(clientSock);
				return;
			}

			size_t headerEnd = raw.find("\r\n\r\n");
			if (headerEnd != std::string::npos)
			{
				size_t bodyStart  = headerEnd + 4;
				size_t bodyHave   = raw.size() > bodyStart ? raw.size() - bodyStart : 0;
				while (bodyHave < contentLength)
				{
					buf.assign(buf.size(), 0);
#if defined _WIN32 || defined _WIN64
					int n = recv(clientSock, buf.data(), static_cast<int>(buf.size()) - 1, 0);
#else
					int n = static_cast<int>(recv(clientSock, buf.data(), buf.size() - 1, 0));
#endif
					if (n <= 0) break;
					raw.append(buf.data(), static_cast<size_t>(n));
					bodyHave += static_cast<size_t>(n);
				}
			}
		}
	}

	HttpRequest req = parseRequest(raw);

#if defined(ESP_PLATFORM)
	// Captive Portal Redirect: If the request is a GET, and the Host is not our IP or is a generic captive portal test domain,
	// redirect the user to our landing page. This triggers the OS captive portal prompt.
	bool isLocalHost = (req.host.find("192.168.4.1") != std::string::npos || 
	                    req.host.find("localhost") != std::string::npos ||
	                    req.host.find("pocketdial") != std::string::npos ||
	                    _ip == "0.0.0.0" || 
	                    req.host.find(_ip) != std::string::npos);

	if (req.method == "GET" && !isLocalHost && req.path != "/api/status" && req.path != "/api/wifi/scan")
	{
		sendRedirect(clientSock, "http://192.168.4.1/");
		closeSocket(clientSock);
		return;
	}
#endif

	// Route
	if (req.method == "GET" && (req.path == "/" || req.path == "/index.html"))
	{
		sendHtml(clientSock, req);
	}
	else if (req.method == "GET" && isProvisioningConfigPath(req.path))
	{
		// Issue #35: GET /config/<mac>.cfg, e.g. GET /config/805ec079c37f.cfg —
		// a phone's own auto-provisioning fetch, so intentionally NOT
		// session-gated (a booting phone has no session cookie to present).
		// The MAC itself is the only credential: it's not guessable (2^48
		// space) and only served for a MAC already in the adopted-device
		// registry, so an unrelated prober learns nothing by guessing.
		sendConfigCfg(clientSock, req.path.substr(8, 12));
	}
	else if (req.method == "GET" && req.path == "/api/status")
	{
		sendApiStatus(clientSock);
	}
	else if (req.method == "POST" && req.path == "/api/kill")
	{
		if (requireAdmin(clientSock, req, true))
		{
			sendApiKill(clientSock, req.body);
		}
	}
	else if (req.method == "GET" && req.path == "/api/cdr")
	{
		// Read-only Call Detail Records — ungated like /api/status.
		sendApiCdr(clientSock);
	}
	else if (req.method == "GET" && req.path == "/api/pcap")
	{
		// Session-gated (see sendApiPcap): full message bytes are more sensitive
		// than /api/cdr's call metadata.
		if (requireAdmin(clientSock, req, false))
		{
			sendApiPcap(clientSock);
		}
	}
	else if (req.method == "GET" && req.path == "/api/trace")
	{
		// Same sensitivity/gate as /api/pcap — this is the same capture ring.
		if (requireAdmin(clientSock, req, false))
		{
			sendApiTrace(clientSock);
		}
	}
	else if (req.method == "GET" && req.path == "/api/diagnostics/pcap")
	{
		// Issue #33: the path the original feature request actually asked for.
		// Deliberately a second route to the SAME handler as /api/pcap rather
		// than an HTTP redirect — a plain `curl -o dump.pcap .../pcap` should
		// work without `-L`, and there is no second capture mechanism here:
		// sendApiPcap() reads the same PcapCapture ring either way. Same
		// sensitivity/gate as /api/pcap for the same reason.
		if (requireAdmin(clientSock, req, false))
		{
			sendApiPcap(clientSock);
		}
	}
	else if (req.method == "POST" && req.path == "/api/dnd")
	{
		// Mutating: same gate as /api/kill (same-origin + auth once provisioned).
		if (requireAdmin(clientSock, req, true))
		{
			sendApiDnd(clientSock, req.body);
		}
	}
	else if (req.method == "POST" && req.path == "/api/forward")
	{
		// Mutating: same gate as /api/dnd (same-origin + auth once provisioned).
		if (requireAdmin(clientSock, req, true))
		{
			sendApiForward(clientSock, req.body);
		}
	}
	else if (req.method == "POST" && req.path == "/api/group")
	{
		// Mutating: same gate as /api/dnd (same-origin + auth once provisioned).
		if (requireAdmin(clientSock, req, true))
		{
			sendApiGroup(clientSock, req.body);
		}
	}
	else if (req.method == "POST" && req.path == "/api/dialplan")
	{
		// Mutating: same gate as /api/group (same-origin + auth once provisioned).
		if (requireAdmin(clientSock, req, true))
		{
			sendApiDialPlan(clientSock, req.body);
		}
	}
	else if (req.method == "GET" && req.path == "/api/wifi/scan")
	{
		sendApiWifiScan(clientSock);
	}
	else if (req.method == "POST" && req.path == "/api/wifi/connect")
	{
		if (requireAdmin(clientSock, req, true))
		{
			sendApiWifiConnect(clientSock, req.body);
		}
	}
	else if (req.method == "POST" && req.path == "/api/wifi/mode_ap")
	{
		if (requireAdmin(clientSock, req, true))
		{
			sendApiWifiModeAp(clientSock);
		}
	}
	else if (req.method == "POST" && req.path == "/api/configuring")
	{
		// "I'm configuring" — hold the captive-portal decay so it doesn't switch
		// to Standalone out from under the user. Previously ungated entirely on a
		// "harmless" argument; it still moves device state on a POST, so it now
		// takes the standard gate. Unprovisioned (i.e. mid-onboarding, which is the
		// only time the captive portal calls it) requireAdmin admits it unchanged.
		if (requireAdmin(clientSock, req, true))
		{
			sendApiConfiguring(clientSock);
		}
	}
	else if (req.method == "POST" && req.path == "/api/factory-reset")
	{
		if (requireAdmin(clientSock, req, true))
		{
			sendApiFactoryReset(clientSock, req.body);
		}
	}
	else if (req.method == "GET" && req.path == "/api/ap-security")
	{
		// Returns the AP passphrase in clear to an authenticated admin — that is
		// the point: on the headless builds this is the only way to read it.
		if (requireAdmin(clientSock, req, false))
		{
			sendApiApSecurity(clientSock);
		}
	}
	else if (req.method == "POST" && req.path == "/api/ap-security")
	{
		if (requireAdmin(clientSock, req, true))
		{
			sendApiApSecuritySet(clientSock, req.body);
		}
	}
	else if (req.method == "GET" && req.path == "/api/registrar")
	{
		if (requireAdmin(clientSock, req, false))
		{
			sendApiRegistrar(clientSock);
		}
	}
	else if (req.method == "POST" && req.path == "/api/registrar")
	{
		if (requireAdmin(clientSock, req, true))
		{
			sendApiRegistrarSet(clientSock, req.body);
		}
	}
	else if (req.method == "POST" && req.path == "/api/registrar/device")
	{
		if (requireAdmin(clientSock, req, true))
		{
			sendApiRegistrarDevice(clientSock, req.body);
		}
	}
	else if (req.method == "GET" && req.path == "/api/admin/status")
	{
		// Read-only: tells the dashboard whether to show a set-PIN or login form.
		sendApiAdminStatus(clientSock, req);
	}
	else if (req.method == "POST" && req.path == "/api/admin/set-pin")
	{
		// Unprovisioned this is onboarding (requireAdmin admits it); provisioned it
		// is a credential change, so it needs the session and the CSRF token.
		if (requireAdmin(clientSock, req, true))
		{
			sendApiAdminSetPin(clientSock, req);
		}
	}
	else if (req.method == "POST" && req.path == "/api/admin/login")
	{
		if (requireSameOrigin(clientSock, req))
		{
			sendApiAdminLogin(clientSock, req);
		}
	}
	else if (req.method == "POST" && req.path == "/api/admin/logout")
	{
		if (requireSameOrigin(clientSock, req))
		{
			sendApiAdminLogout(clientSock, req);
		}
	}
	else if (req.method == "POST" && req.path == "/api/admin/keepalive")
	{
		if (requireAdmin(clientSock, req, true))
		{
			sendApiAdminKeepAlive(clientSock, req);
		}
	}
	else if (req.method == "GET" && req.path == "/api/ota/status")
	{
		// Read-only OTA introspection (partition labels + pending flag). No
		// secrets, so it's readable like /api/status — safe pre-auth.
		sendApiOtaStatus(clientSock);
	}
	else if (req.method == "POST" && req.path == "/api/ota/reboot")
	{
		if (requireAdmin(clientSock, req, true))
		{
			sendApiOtaReboot(clientSock);
		}
	}
	// NOTE: POST /api/ota/upload is handled earlier in handleClient() via the
	// streaming interception (it must bypass the 16 KB buffered body path), so
	// it deliberately does NOT appear in this route table.
	else
	{
		send404(clientSock);
	}

	closeSocket(clientSock);
}

HttpServer::HttpRequest HttpServer::parseRequest(const std::string& raw)
{
	HttpRequest req;

	// Parse request line: "GET /path HTTP/1.1\r\n"
	size_t methodEnd = raw.find(' ');
	if (methodEnd == std::string::npos) return req;
	req.method = raw.substr(0, methodEnd);

	size_t pathStart = methodEnd + 1;
	size_t pathEnd = raw.find(' ', pathStart);
	if (pathEnd == std::string::npos) return req;
	req.path = raw.substr(pathStart, pathEnd - pathStart);

	// Strip query string
	size_t queryPos = req.path.find('?');
	if (queryPos != std::string::npos)
	{
		req.path = req.path.substr(0, queryPos);
	}

	// Efficient, low-overhead line-by-line header scanner (Observation 1)
	size_t pos = raw.find("\r\n");
	if (pos != std::string::npos) {
		pos += 2; // Skip request line
		while (pos < raw.size()) {
			size_t lineEnd = raw.find("\r\n", pos);
			if (lineEnd == std::string::npos) break;
			if (lineEnd == pos) break; // Reached header-body boundary

			std::string line = raw.substr(pos, lineEnd - pos);
			size_t colon = line.find(':');
			if (colon != std::string::npos) {
				std::string hName = line.substr(0, colon);
				std::transform(hName.begin(), hName.end(), hName.begin(), ::tolower);
				
				// Strip trailing whitespaces from name
				while (!hName.empty() && std::isspace(static_cast<unsigned char>(hName.back()))) hName.pop_back();

				if (hName == "origin" || hName == "host" || hName == "cookie" ||
				    hName == "x-csrf") {
					size_t valStart = colon + 1;
					while (valStart < line.size() && std::isspace(static_cast<unsigned char>(line[valStart]))) valStart++;
					std::string hVal = line.substr(valStart);
					while (!hVal.empty() && std::isspace(static_cast<unsigned char>(hVal.back()))) hVal.pop_back();
					if (hName == "origin") req.origin = hVal;
					else if (hName == "host") req.host = hVal;
					else if (hName == "cookie") req.cookie = hVal;
					else if (hName == "x-csrf") req.csrf = hVal;
				}
			}
			pos = lineEnd + 2;
		}
	}

	// Find body (after \r\n\r\n)
	size_t bodyStart = raw.find("\r\n\r\n");
	if (bodyStart != std::string::npos)
	{
		req.body = raw.substr(bodyStart + 4);
	}

	return req;
}

void HttpServer::sendResponseWithHeader(int sock, int statusCode, const std::string& statusText,
                              const std::string& contentType, const std::string& body,
                              const std::string& extraHeader)
{
	std::ostringstream resp;
	resp << "HTTP/1.1 " << statusCode << " " << statusText << "\r\n";
	resp << "Content-Type: " << contentType << "\r\n";
	resp << "Content-Length: " << body.size() << "\r\n";
	// No Access-Control-Allow-Origin header: wildcard CORS would allow any
	// browser tab on the same AP to fire side-effecting POSTs without a preflight.

	// --- Security headers, emitted centrally so no endpoint can forget them ---
	// The dashboard is a single self-contained page with inline <script>/<style>
	// and no external origins, so the policy can be this tight: nothing loads
	// from anywhere, the page cannot be framed, and XHR/fetch is same-origin.
	resp << "Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; "
	        "style-src 'unsafe-inline'; img-src data:; connect-src 'self'; "
	        "form-action 'self'; frame-ancestors 'none'; base-uri 'none'\r\n";
	resp << "X-Frame-Options: DENY\r\n";
	resp << "X-Content-Type-Options: nosniff\r\n";
	// Responses carry call metadata, the CSRF token and (on /api/pcap) raw SIP
	// bytes. None of it should sit in a shared browser cache or on disk.
	resp << "Cache-Control: no-store\r\n";
	// same-origin, not no-referrer: the Referer header stays available as a
	// same-origin signal, and nothing here is linked off-device anyway.
	resp << "Referrer-Policy: same-origin\r\n";
	// Deliberately NO Strict-Transport-Security. The dashboard is plain HTTP on
	// a LAN appliance; pinning HSTS here would make the host unreachable over
	// http:// forever with no way for a user to override it.
	if (!extraHeader.empty())
	{
		resp << extraHeader << "\r\n";
	}
	resp << "Connection: close\r\n";
	resp << "\r\n";
	resp << body;

	std::string data = resp.str();
	const char* ptr = data.c_str();
	size_t remaining = data.size();
	while (remaining > 0)
	{
#if defined _WIN32 || defined _WIN64
		int sent = ::send(sock, ptr, static_cast<int>(remaining), 0);
#else
		int sent = static_cast<int>(::send(sock, ptr, remaining, 0));
#endif
		if (sent <= 0) break;
		ptr += sent;
		remaining -= static_cast<size_t>(sent);
	}
}

void HttpServer::sendResponse(int sock, int statusCode, const std::string& statusText,
                              const std::string& contentType, const std::string& body)
{
	sendResponseWithHeader(sock, statusCode, statusText, contentType, body, "");
}

void HttpServer::sendHtml(int sock, const HttpRequest& req)
{
	std::string page(CGA_INDEX_HTML);

	// Bind the page to this session's CSRF token. It is rendered INTO the
	// document rather than set as a cookie: the browser attaches cookies to
	// same-site requests on its own, so a cookie would be forged as easily as the
	// session itself, whereas a value a cross-origin page cannot read has to be
	// echoed back deliberately by our own JavaScript.
	//
	// An unauthenticated load substitutes an empty token, which is correct: there
	// is no session yet, and the login response carries the token the page then
	// uses without needing a reload.
	const std::string token = AdminAuth::sessionCsrf(sessionToken(req));
	const std::string marker = "__PD_CSRF__";
	const size_t at = page.find(marker);
	if (at != std::string::npos)
	{
		page.replace(at, marker.size(), token);
	}

	sendResponse(sock, 200, "OK", "text/html; charset=utf-8", page);
}

// Helper: JSON-escape a string. Beyond the five named C0 escapes, JSON (RFC
// 8259 §7) requires every other U+0000-U+001F control byte to be escaped too
// (as \u00XX) — not just the printable-looking ones. This matters here
// because #105 made /api/trace/#api/pcap capable of carrying the raw,
// unmodified bytes of an inbound SIP packet: a malformed-but-tolerated packet
// containing a stray control byte (e.g. 0x01, 0x1F) would otherwise land in
// the JSON body unescaped, producing invalid JSON that breaks the dashboard's
// JSON.parse() and silently freezes the live trace view.
static std::string jsonEscape(const std::string& s)
{
	static const char* hex = "0123456789abcdef";
	std::string out;
	out.reserve(s.size() + 8);
	for (unsigned char c : s)
	{
		switch (c)
		{
			case '"':  out += "\\\""; break;
			case '\\': out += "\\\\"; break;
			case '\n': out += "\\n";  break;
			case '\r': out += "\\r";  break;
			case '\t': out += "\\t";  break;
			default:
				if (c < 0x20)
				{
					out += "\\u00";
					out += hex[(c >> 4) & 0x0F];
					out += hex[c & 0x0F];
				}
				else
				{
					out += static_cast<char>(c);
				}
		}
	}
	return out;
}

void HttpServer::sendApiStatus(int sock)
{
	uint64_t uptimeMs = currentTimeMs() - _startTime;
	uint64_t uptimeSec = uptimeMs / 1000;

	std::vector<std::pair<std::string, std::string>> clients;
	std::vector<std::tuple<std::string, std::string, std::string, int>> sessions;
	std::vector<std::string> dndExtensions;
	std::vector<std::tuple<std::string, std::string, std::string, std::string>> forwards;
	std::vector<std::tuple<std::string, std::string, std::string>> ringGroups;
	std::vector<std::tuple<std::string, std::string, std::string>> dialRules;
	uint64_t packets = 0;
	uint64_t dropped = 0;

	RequestsHandler* handler = _handler.load(std::memory_order_acquire);
	if (handler != nullptr)
	{
		clients = handler->getActiveClients();
		sessions = handler->getActiveSessions();
		dndExtensions = handler->getDndExtensions();
		forwards = handler->getForwards();
		ringGroups = handler->getRingGroups();
		dialRules = handler->getDialRules();
		packets = handler->getPacketsProcessed();
		dropped = handler->getPacketsDropped();   // Issue #38
	}

	std::string displayIp = _ip;
	if (displayIp == "0.0.0.0")
	{
		displayIp = getPrimaryLocalIP();
	}

	std::ostringstream json;
	json << "{";
	json << "\"ip\":\"" << jsonEscape(displayIp) << "\",";
	json << "\"port\":" << 5060 << ",";
	json << "\"httpPort\":" << _port << ",";
	json << "\"uptime\":" << uptimeSec << ",";
	json << "\"packetsProcessed\":" << packets << ",";
	json << "\"packetsDropped\":" << dropped << ",";

	// Clients array
	json << "\"clients\":[";
	for (size_t i = 0; i < clients.size(); i++)
	{
		if (i > 0) json << ",";
		json << "{\"number\":\"" << jsonEscape(clients[i].first)
		     << "\",\"address\":\"" << jsonEscape(clients[i].second) << "\"}";
	}
	json << "],";

	// Sessions array
	json << "\"sessions\":[";
	for (size_t i = 0; i < sessions.size(); i++)
	{
		if (i > 0) json << ",";
		int durationSec = std::get<3>(sessions[i]);
		int hrs = durationSec / 3600;
		int mins = (durationSec % 3600) / 60;
		int secs = durationSec % 60;
		char durationBuf[32]{};
		if (hrs > 0)
		{
			snprintf(durationBuf, sizeof(durationBuf), "%02d:%02d:%02d", hrs, mins, secs);
		}
		else
		{
			snprintf(durationBuf, sizeof(durationBuf), "%02d:%02d", mins, secs);
		}

		json << "{\"caller\":\"" << jsonEscape(std::get<0>(sessions[i]))
		     << "\",\"callee\":\"" << jsonEscape(std::get<1>(sessions[i]))
		     << "\",\"state\":\"" << jsonEscape(std::get<2>(sessions[i]))
		     << "\",\"duration\":\"" << durationBuf << "\"}";
	}
	json << "],";

	// DND array: extensions currently in Do Not Disturb (Phase 2).
	json << "\"dnd\":[";
	for (size_t i = 0; i < dndExtensions.size(); i++)
	{
		if (i > 0) json << ",";
		json << "\"" << jsonEscape(dndExtensions[i]) << "\"";
	}
	json << "],";

	// Call-forward array (Class A sweep): per-extension always/busy/noanswer targets.
	json << "\"forwards\":[";
	for (size_t i = 0; i < forwards.size(); i++)
	{
		if (i > 0) json << ",";
		json << "{\"extension\":\"" << jsonEscape(std::get<0>(forwards[i]))
		     << "\",\"always\":\""   << jsonEscape(std::get<1>(forwards[i]))
		     << "\",\"busy\":\""     << jsonEscape(std::get<2>(forwards[i]))
		     << "\",\"noanswer\":\"" << jsonEscape(std::get<3>(forwards[i])) << "\"}";
	}
	json << "],";

	// Ring/hunt-group array (Class A sweep): group ext, mode, comma-joined members.
	json << "\"groups\":[";
	for (size_t i = 0; i < ringGroups.size(); i++)
	{
		if (i > 0) json << ",";
		json << "{\"extension\":\"" << jsonEscape(std::get<0>(ringGroups[i]))
		     << "\",\"mode\":\""     << jsonEscape(std::get<1>(ringGroups[i]))
		     << "\",\"members\":\""  << jsonEscape(std::get<2>(ringGroups[i])) << "\"}";
	}
	json << "],";

	// Dial-plan rules (Issue #69). Emitted in TABLE ORDER — this array's order is
	// load-bearing (first match wins), unlike the sets above.
	json << "\"dialplan\":[";
	for (size_t i = 0; i < dialRules.size(); i++)
	{
		if (i > 0) json << ",";
		json << "{\"pattern\":\"" << jsonEscape(std::get<0>(dialRules[i]))
		     << "\",\"action\":\"" << jsonEscape(std::get<1>(dialRules[i]))
		     << "\",\"target\":\"" << jsonEscape(std::get<2>(dialRules[i])) << "\"}";
	}
	json << "]";

	json << "}";

	sendResponse(sock, 200, "OK", "application/json", json.str());
}

void HttpServer::sendApiKill(int sock, const std::string& body)
{
	// Parse "extension=XXXX" from the body
	std::string ext;
	std::string prefix = "extension=";
	size_t pos = body.find(prefix);
	if (pos != std::string::npos)
	{
		ext = body.substr(pos + prefix.size());
		// Trim whitespace / newlines
		while (!ext.empty() && (ext.back() == '\r' || ext.back() == '\n' || ext.back() == ' '))
			ext.pop_back();
	}

	if (ext.empty())
	{
		sendResponse(sock, 400, "Bad Request", "application/json",
		             "{\"error\":\"missing extension parameter\"}");
		return;
	}

	if (RequestsHandler* handler = _handler.load(std::memory_order_acquire))
	{
		handler->forceDisconnect(ext);
	}
	sendResponse(sock, 200, "OK", "application/json",
	             "{\"status\":\"ok\",\"disconnected\":\"" + jsonEscape(ext) + "\"}");
}

void HttpServer::sendApiCdr(int sock)
{
	std::vector<CallDetailRecord> records;
	if (RequestsHandler* handler = _handler.load(std::memory_order_acquire))
	{
		records = handler->getCallDetailRecords();   // newest first, thread-safe copy
	}

	uint64_t nowMs = currentTimeMs();   // same steady-clock basis as the CDR startMs

	std::ostringstream json;
	json << "[";
	for (size_t i = 0; i < records.size(); i++)
	{
		if (i > 0) json << ",";
		const CallDetailRecord& r = records[i];
		// "ageSec": seconds since the call started, derived from the shared
		// steady-clock basis (no wall clock / RTC is guaranteed on the device).
		uint64_t ageSec = (nowMs >= r.startMs) ? (nowMs - r.startMs) / 1000 : 0;
		json << "{\"caller\":\"" << jsonEscape(r.caller) << "\","
		     << "\"callee\":\"" << jsonEscape(r.callee) << "\","
		     << "\"startMs\":" << r.startMs << ","
		     << "\"ageSec\":" << ageSec << ","
		     << "\"duration\":" << r.durationSec << ","
		     << "\"result\":\"" << cdrResultToString(r.result) << "\"}";
	}
	json << "]";

	sendResponse(sock, 200, "OK", "application/json", json.str());
}

void HttpServer::sendApiPcap(int sock)
{
	std::string pcap;
	if (RequestsHandler* handler = _handler.load(std::memory_order_acquire))
	{
		pcap = handler->getPcapCapture();
	}
	// No same-origin check: this is a plain-download GET (an admin clicking a
	// dashboard link, or curl/wget with the session cookie), not a
	// state-mutating action — the same-origin gate on every other admin
	// endpoint exists to stop a malicious page from silently POSTing through an
	// admin's authenticated browser, which doesn't apply to fetching a file.
	// SameSite=Strict on pd_session (see /api/admin/login) already keeps a
	// cross-site page from riding the admin's session to reach this at all.
	sendResponseWithHeader(sock, 200, "OK", "application/vnd.tcpdump.pcap", pcap,
		"Content-Disposition: attachment; filename=\"pocket-dial.pcap\"");
}

void HttpServer::sendApiTrace(int sock)
{
	std::vector<PcapCapture::TraceRecord> records;
	if (RequestsHandler* handler = _handler.load(std::memory_order_acquire))
	{
		records = handler->getTraceRecords();
	}

	// Whole current ring every poll, not "since N": the ring is small
	// (POCKETDIAL_PCAP_RING_SIZE, default 64) and this is a LAN debugging
	// aid polled every second or two, so re-sending it is cheap — and it
	// avoids the server needing to track any per-client polling state. The
	// dashboard filters to unseen `seq` values client-side.
	std::ostringstream json;
	json << "[";
	for (std::size_t i = 0; i < records.size(); ++i)
	{
		if (i > 0) json << ",";
		const auto& r = records[i];
		json << "{\"seq\":" << r.seq << ","
		     << "\"tsUs\":" << r.tsUs << ","
		     << "\"dir\":\"" << (r.outbound ? "out" : "in") << "\","
		     << "\"peer\":\"" << jsonEscape(r.peer) << "\","
		     << "\"text\":\"" << jsonEscape(r.text) << "\"}";
	}
	json << "]";

	sendResponse(sock, 200, "OK", "application/json", json.str());
}

bool HttpServer::isProvisioningConfigPath(const std::string& path)
{
	static const std::string prefix = "/config/";
	static const std::string suffix = ".cfg";
	if (path.size() != prefix.size() + 12 + suffix.size()) return false;
	if (path.compare(0, prefix.size(), prefix) != 0) return false;
	if (path.compare(path.size() - suffix.size(), suffix.size(), suffix) != 0) return false;
	for (std::size_t i = prefix.size(); i < prefix.size() + 12; ++i)
	{
		char c = path[i];
		bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
		if (!hex) return false;
	}
	return true;
}

void HttpServer::sendConfigCfg(int sock, const std::string& mac)
{
	RequestsHandler* handler = _handler.load(std::memory_order_acquire);
	auto info = handler ? handler->findProvisioningInfo(mac) : std::nullopt;
	if (!info)
	{
		send404(sock);
		return;
	}

	// Same IP resolution as sendApiStatus; SIP port is hardcoded 5060 there
	// too (this codebase doesn't support running the SIP listener on a
	// non-default port).
	std::string activeIp = (_ip == "0.0.0.0") ? getPrimaryLocalIP() : _ip;
	std::string cfg = provisioning::yealinkConfigFor(info->extension, activeIp, 5060,
		info->authRequired);
	if (cfg.empty())
	{
		// The builder refused the extension (CR/LF -- Issue #107). There is no safe
		// partial config to serve, so this is a miss, not a 200 with an empty body.
		send404(sock);
		return;
	}
	sendResponse(sock, 200, "OK", "text/plain", cfg);
}

void HttpServer::sendApiDnd(int sock, const std::string& body)
{
	std::string ext = getFormParam(body, "extension");
	std::string on  = getFormParam(body, "on");

	if (ext.empty())
	{
		sendResponse(sock, 400, "Bad Request", "application/json",
		             "{\"error\":\"missing extension parameter\"}");
		return;
	}

	// Reject the virtual extensions: DND must never affect echo (777), broadcast
	// (999) or the anchor media bridge (555) — none are real endpoints.
	if (ext == "777" || ext == "999" || ext == "555")
	{
		sendResponse(sock, 400, "Bad Request", "application/json",
		             "{\"error\":\"cannot set DND on a virtual extension\"}");
		return;
	}

	// Accept 1/true/on as enable; anything else (incl. "0") disables.
	bool enable = (on == "1" || on == "true" || on == "on");

	if (RequestsHandler* handler = _handler.load(std::memory_order_acquire))
	{
		handler->setDnd(ext, enable);
	}

	sendResponse(sock, 200, "OK", "application/json",
	             "{\"status\":\"ok\",\"extension\":\"" + jsonEscape(ext) +
	             "\",\"dnd\":" + (enable ? "true" : "false") + "}");
}

void HttpServer::sendApiForward(int sock, const std::string& body)
{
	// Params: extension, trigger ("always"|"busy"|"noanswer"), target (empty=clear).
	std::string ext     = getFormParam(body, "extension");
	std::string trigger = getFormParam(body, "trigger");
	std::string target  = getFormParam(body, "target");

	if (ext.empty() || trigger.empty())
	{
		sendResponse(sock, 400, "Bad Request", "application/json",
		             "{\"error\":\"missing extension or trigger parameter\"}");
		return;
	}
	if (trigger != "always" && trigger != "busy" && trigger != "noanswer")
	{
		sendResponse(sock, 400, "Bad Request", "application/json",
		             "{\"error\":\"trigger must be always|busy|noanswer\"}");
		return;
	}
	if (ext == "777" || ext == "999" || ext == "555")
	{
		sendResponse(sock, 400, "Bad Request", "application/json",
		             "{\"error\":\"cannot forward a virtual extension\"}");
		return;
	}

	if (RequestsHandler* handler = _handler.load(std::memory_order_acquire))
	{
		handler->setForward(ext, trigger, target);
	}

	sendResponse(sock, 200, "OK", "application/json",
	             "{\"status\":\"ok\",\"extension\":\"" + jsonEscape(ext) +
	             "\",\"trigger\":\"" + jsonEscape(trigger) +
	             "\",\"target\":\"" + jsonEscape(target) + "\"}");
}

void HttpServer::sendApiGroup(int sock, const std::string& body)
{
	// Params: extension (group ext), members (comma/space list), mode ("ringall"|"hunt").
	// An empty member list deletes the group.
	std::string ext     = getFormParam(body, "extension");
	std::string members = getFormParam(body, "members");
	std::string mode    = getFormParam(body, "mode");

	if (ext.empty())
	{
		sendResponse(sock, 400, "Bad Request", "application/json",
		             "{\"error\":\"missing extension parameter\"}");
		return;
	}
	if (ext == "777" || ext == "999" || ext == "555")
	{
		sendResponse(sock, 400, "Bad Request", "application/json",
		             "{\"error\":\"cannot use a reserved extension as a group\"}");
		return;
	}
	if (mode.empty()) mode = "ringall";
	if (mode != "ringall" && mode != "hunt")
	{
		sendResponse(sock, 400, "Bad Request", "application/json",
		             "{\"error\":\"mode must be ringall|hunt\"}");
		return;
	}

	if (RequestsHandler* handler = _handler.load(std::memory_order_acquire))
	{
		handler->setRingGroup(ext, members, mode);
	}

	sendResponse(sock, 200, "OK", "application/json",
	             "{\"status\":\"ok\",\"extension\":\"" + jsonEscape(ext) +
	             "\",\"mode\":\"" + jsonEscape(mode) +
	             "\",\"members\":\"" + jsonEscape(members) + "\"}");
}

void HttpServer::sendApiDialPlan(int sock, const std::string& body)
{
	// Issue #69. Params: pattern (the rule's key), action ("group"|"page"|"park"),
	// target (the group/zone/orbit extension). An empty target deletes the rule.
	// The dial plan is ORDERED and first-match-wins, so an existing pattern is
	// edited in place (keeping its position) and a new one is appended — see
	// RequestsHandler::setDialRule, which owns the full validation and the
	// POCKETDIAL_MAX_DIAL_RULES cap.
	std::string pattern = getFormParam(body, "pattern");
	std::string action  = getFormParam(body, "action");
	std::string target  = getFormParam(body, "target");

	if (pattern.empty())
	{
		sendResponse(sock, 400, "Bad Request", "application/json",
		             "{\"error\":\"missing pattern parameter\"}");
		return;
	}
	if (!pbx::isDialTokenSafe(pattern))
	{
		sendResponse(sock, 400, "Bad Request", "application/json",
		             "{\"error\":\"pattern may contain only letters, digits, '#' and '*'\"}");
		return;
	}
	if (pattern == "777" || pattern == "999" || pattern == "440" || pattern == "555")
	{
		sendResponse(sock, 400, "Bad Request", "application/json",
		             "{\"error\":\"cannot use a reserved extension as a dial-plan pattern\"}");
		return;
	}

	// A delete only needs the pattern; everything else is validated for an upsert.
	if (!target.empty())
	{
		if (action.empty()) action = "group";
		pbx::DialActionType parsed;
		if (!pbx::parseDialAction(action, parsed))
		{
			sendResponse(sock, 400, "Bad Request", "application/json",
			             "{\"error\":\"action must be group|page|park\"}");
			return;
		}
		if (!pbx::isDialTokenSafe(target))
		{
			sendResponse(sock, 400, "Bad Request", "application/json",
			             "{\"error\":\"target may contain only letters, digits, '#' and '*'\"}");
			return;
		}
		if (parsed == pbx::DialActionType::PageZone && !pbx::isPageZoneExt(target))
		{
			sendResponse(sock, 400, "Bad Request", "application/json",
			             "{\"error\":\"page target must be a paging zone (980-989)\"}");
			return;
		}
		if (parsed == pbx::DialActionType::ParkOrbit && !pbx::isParkOrbitExt(target))
		{
			sendResponse(sock, 400, "Bad Request", "application/json",
			             "{\"error\":\"park target must be a park orbit\"}");
			return;
		}
	}

	if (RequestsHandler* handler = _handler.load(std::memory_order_acquire))
	{
		handler->setDialRule(pattern, action, target);
	}

	sendResponse(sock, 200, "OK", "application/json",
	             "{\"status\":\"ok\",\"pattern\":\"" + jsonEscape(pattern) +
	             "\",\"action\":\"" + jsonEscape(action) +
	             "\",\"target\":\"" + jsonEscape(target) + "\"}");
}

bool HttpServer::isSameOrigin(const HttpRequest& req) const
{
	// No Origin header means a direct request (browser nav, curl, etc.) — allow.
	if (req.origin.empty()) return true;

	// Strip the scheme from the Origin (e.g. "http://192.168.4.1:8080" → "192.168.4.1:8080")
	std::string originHost = req.origin;
	size_t schemeEnd = originHost.find("://");
	if (schemeEnd != std::string::npos)
		originHost = originHost.substr(schemeEnd + 3);

	// Split "host:port" (port optional → empty string when absent).
	auto splitHostPort = [](const std::string& h) -> std::pair<std::string, std::string> {
		size_t colon = h.find(':');
		if (colon != std::string::npos) return { h.substr(0, colon), h.substr(colon + 1) };
		return { h, std::string() };
	};

	auto originParts = splitHostPort(originHost);
	auto hostParts   = splitHostPort(req.host);
	const std::string& cleanOrigin = originParts.first;
	const std::string& cleanHost   = hostParts.first;

	// Host header must be our local IP or local mDNS hostname or localhost
	std::string activeIp = (_ip == "0.0.0.0") ? getPrimaryLocalIP() : _ip;
	bool hostValid = (cleanHost == activeIp ||
	                  cleanHost == "192.168.4.1" ||
	                  cleanHost == "pocketdial.local" ||
	                  cleanHost == "localhost" ||
	                  cleanHost == "127.0.0.1");

	if (!hostValid || cleanOrigin != cleanHost) return false;

	// When BOTH carry an explicit port, they must match — a page served from a
	// different port is a different origin. If either omits the port we fall back
	// to the host-only check (browsers elide the default :80/:443, so requiring a
	// port there would reject otherwise-legitimate same-origin requests).
	if (!originParts.second.empty() && !hostParts.second.empty() &&
	    originParts.second != hostParts.second)
	{
		return false;
	}
	return true;
}

std::string HttpServer::cookieValue(const HttpRequest& req, const std::string& name)
{
	// Cookie header is "k1=v1; k2=v2; ...". Find name= as a token boundary.
	const std::string& c = req.cookie;
	if (c.empty()) return "";

	size_t pos = 0;
	while (pos < c.size())
	{
		// Skip leading spaces / separators.
		while (pos < c.size() && (c[pos] == ' ' || c[pos] == ';')) ++pos;
		size_t eq = c.find('=', pos);
		if (eq == std::string::npos) break;
		std::string k = c.substr(pos, eq - pos);
		size_t valStart = eq + 1;
		size_t valEnd = c.find(';', valStart);
		std::string v = (valEnd == std::string::npos)
			? c.substr(valStart)
			: c.substr(valStart, valEnd - valStart);
		// Trim surrounding whitespace from the value.
		while (!v.empty() && (v.front() == ' ')) v.erase(v.begin());
		while (!v.empty() && (v.back() == ' ' || v.back() == '\r' || v.back() == '\n')) v.pop_back();
		if (k == name) return v;
		if (valEnd == std::string::npos) break;
		pos = valEnd + 1;
	}
	return "";
}

std::string HttpServer::sessionToken(const HttpRequest& req) const
{
	return cookieValue(req, "pd_session");
}

bool HttpServer::requireSameOrigin(int sock, const HttpRequest& req)
{
	if (!isSameOrigin(req))
	{
		sendResponse(sock, 403, "Forbidden", "application/json",
		             "{\"error\":\"cross-origin request rejected\"}");
		return false;
	}
	return true;
}

bool HttpServer::requireAdmin(int sock, const HttpRequest& req, bool needCsrf)
{
	// 1. Same-origin. A request with NO Origin header is admitted by design (see
	//    isSameOrigin): curl, native clients and tests/http/test_api.sh do not
	//    send one. That is precisely why step 3 exists — the Origin check is a
	//    browser-only control and cannot stand alone.
	if (!requireSameOrigin(sock, req))
	{
		return false;
	}

	// 2. Session. An unprovisioned device keeps its pre-auth behaviour so
	//    captive-portal onboarding still works and the device can be claimed at
	//    all (docs/THREAT_MODEL.md §5.1 — this window is deliberate and is closed
	//    by provisioning a PIN as the first onboarding step).
	if (!AdminAuth::isProvisioned())
	{
		return true;
	}

	const std::string token = sessionToken(req);
	if (!AdminAuth::validateSession(token))
	{
		sendResponse(sock, 401, "Unauthorized", "application/json",
		             "{\"error\":\"authentication required\"}");
		return false;
	}

	// 3. CSRF, for mutating requests only, and only once there is a session to
	//    bind the token to. This is what closes the hole the Origin check leaves
	//    open (docs/THREAT_MODEL.md T-2): a page that can drive fetch() at us
	//    still cannot read a value that was rendered into our own document.
	if (needCsrf && !AdminAuth::validateCsrf(token, req.csrf))
	{
		sendResponse(sock, 403, "Forbidden", "application/json",
		             "{\"error\":\"missing or invalid CSRF token\"}");
		return false;
	}

	return true;
}

bool HttpServer::isAuthed(const HttpRequest& req) const
{
	std::string token = cookieValue(req, "pd_session");
	if (token.empty()) return false;
	return AdminAuth::validateSession(token);
}

void HttpServer::send404(int sock)
{
	sendResponse(sock, 404, "Not Found", "text/plain", "404 Not Found");
}

void HttpServer::closeSocket(int sock)
{
#if defined(__linux__) || defined(ESP_PLATFORM)
	close(sock);
#elif defined _WIN32 || defined _WIN64
	closesocket(sock);
#endif
}

uint64_t HttpServer::currentTimeMs() const
{
	return static_cast<uint64_t>(
		std::chrono::duration_cast<std::chrono::milliseconds>(
			std::chrono::steady_clock::now().time_since_epoch()
		).count()
	);
}

// Helpers for URL decoding and parsing post/form params
static std::string urlDecode(const std::string& src)
{
	std::string ret;
	char ch = '\0';
	unsigned int ii = 0;
	for (size_t pos = 0; pos < src.length(); ++pos) {
		if (src[pos] == '+') {
			ret += ' ';
		} else if (src[pos] == '%') {
			if (pos + 2 < src.length() && 
				sscanf(src.substr(pos + 1, 2).c_str(), "%x", &ii) == 1) {
				ch = static_cast<char>(ii);
				ret += ch;
				pos += 2;
			} else {
				ret += src[pos];
			}
		} else {
			ret += src[pos];
		}
	}
	return ret;
}

static std::string getFormParam(const std::string& body, const std::string& key)
{
	const std::string needle = key + "=";
	// Match the key only at a parameter boundary: the start of the body, or
	// immediately after an '&'. A bare find() mis-matches a key that is a suffix
	// of an earlier one — e.g. searching "on=" inside "extension=101&on=1" finds
	// the "n=" of "extensio[n=]101" and returns "101", so DND silently inverted.
	size_t pos = 0;
	for (;;)
	{
		pos = body.find(needle, pos);
		if (pos == std::string::npos) return "";
		if (pos == 0 || body[pos - 1] == '&') break;   // real token boundary
		pos += needle.length();                        // false hit — keep scanning
	}
	size_t start = pos + needle.length();
	size_t end = body.find('&', start);
	std::string val;
	if (end == std::string::npos) {
		val = body.substr(start);
	} else {
		val = body.substr(start, end - start);
	}
	while (!val.empty() && (val.back() == '\r' || val.back() == '\n' || val.back() == ' ')) {
		val.pop_back();
	}
	return urlDecode(val);
}

void HttpServer::sendApiWifiScan(int sock)
{
#if defined(POCKETDIAL_HAS_WIFI)
	// Switch mode to AP+STA so we can scan
	wifi_mode_t current_mode;
	if (esp_wifi_get_mode(&current_mode) == ESP_OK) {
		if (current_mode == WIFI_MODE_AP) {
			esp_wifi_set_mode(WIFI_MODE_APSTA);
		}
	}

	wifi_scan_config_t scan_config = {};
	scan_config.show_hidden = true;
	
	esp_err_t err = esp_wifi_scan_start(&scan_config, true);
	if (err != ESP_OK) {
		sendResponse(sock, 500, "Internal Server Error", "application/json", 
		             "{\"error\":\"WiFi scan start failed\",\"code\":" + std::to_string(err) + "}");
		return;
	}

	uint16_t ap_count = 0;
	esp_wifi_scan_get_ap_num(&ap_count);
	
	std::vector<wifi_ap_record_t> ap_records(ap_count);
	if (ap_count > 0) {
		esp_wifi_scan_get_ap_records(&ap_count, ap_records.data());
	}

	std::ostringstream json;
	json << "{\"networks\":[";
	for (uint16_t i = 0; i < ap_count; ++i) {
		if (i > 0) json << ",";
		std::string ssid(reinterpret_cast<char*>(ap_records[i].ssid));
		int rssi = ap_records[i].rssi;
		std::string enc = "OPEN";
		switch (ap_records[i].authmode) {
			case WIFI_AUTH_WEP: enc = "WEP"; break;
			case WIFI_AUTH_WPA_PSK: enc = "WPA"; break;
			case WIFI_AUTH_WPA2_PSK: enc = "WPA2"; break;
			case WIFI_AUTH_WPA_WPA2_PSK: enc = "WPA/WPA2"; break;
			case WIFI_AUTH_WPA2_ENTERPRISE: enc = "WPA2 Enterprise"; break;
			case WIFI_AUTH_WPA3_PSK: enc = "WPA3"; break;
			case WIFI_AUTH_WPA2_WPA3_PSK: enc = "WPA2/WPA3"; break;
			default: break;
		}
		json << "{\"ssid\":\"" << jsonEscape(ssid) << "\",\"rssi\":" << rssi 
		     << ",\"encryption\":\"" << jsonEscape(enc) << "\"}";
	}
	json << "]}";

	sendResponse(sock, 200, "OK", "application/json", json.str());
#else
	sendResponse(sock, 200, "OK", "application/json", 
	             "{\"networks\":[], \"note\":\"WiFi scan not available on desktop\"}");
#endif
}

void HttpServer::sendApiWifiConnect(int sock, const std::string& body)
{
	std::string ssid = getFormParam(body, "ssid");
	std::string password = getFormParam(body, "password");

	if (ssid.empty())
	{
		sendResponse(sock, 400, "Bad Request", "application/json",
		             "{\"error\":\"missing ssid parameter\"}");
		return;
	}

#if defined(POCKETDIAL_HAS_WIFI)
	nvs_handle_t nvs_handle;
	esp_err_t err = nvs_open("storage", NVS_READWRITE, &nvs_handle);
	if (err == ESP_OK) {
		nvs_set_u8(nvs_handle, "wifi_mode", 1); // 1 = STATION
		nvs_set_str(nvs_handle, "wifi_ssid", ssid.c_str());
		nvs_set_str(nvs_handle, "wifi_pass", password.c_str());
		nvs_commit(nvs_handle);
		nvs_close(nvs_handle);
	}

	sendResponse(sock, 200, "OK", "application/json",
	             "{\"status\":\"ok\",\"message\":\"WiFi credentials saved. Rebooting to Station Mode...\"}");

	// Create a background task to restart after 1 second
	xTaskCreate([](void*) {
		vTaskDelay(pdMS_TO_TICKS(1000));
		esp_restart();
	}, "restart_task", 2048, NULL, 5, NULL);
#else
	(void)password;
	sendResponse(sock, 501, "Not Implemented", "application/json",
	             "{\"error\":\"WiFi connect not available on desktop\"}");
#endif
}

void HttpServer::sendApiWifiModeAp(int sock)
{
#if defined(POCKETDIAL_HAS_WIFI)
	nvs_handle_t nvs_handle;
	esp_err_t err = nvs_open("storage", NVS_READWRITE, &nvs_handle);
	if (err == ESP_OK) {
		nvs_set_u8(nvs_handle, "wifi_mode", 2); // 2 = AP (Standalone)
		nvs_commit(nvs_handle);
		nvs_close(nvs_handle);
	}

	sendResponse(sock, 200, "OK", "application/json",
	             "{\"status\":\"ok\",\"message\":\"Operational mode set to Standalone AP. Rebooting...\"}");

	// Create a background task to restart after 1 second
	xTaskCreate([](void*) {
		vTaskDelay(pdMS_TO_TICKS(1000));
		esp_restart();
	}, "restart_task", 2048, NULL, 5, NULL);
#else
	sendResponse(sock, 501, "Not Implemented", "application/json",
	             "{\"error\":\"WiFi mode select not available on desktop\"}");
#endif
}

void HttpServer::sendApiConfiguring(int sock)
{
	// Pause the captive-portal decay watchdog: the user is actively configuring, so don't
	// auto-switch to Standalone. Held until they save a mode or factory-reset (both reboot).
	g_decayHold = true;
	sendResponse(sock, 200, "OK", "application/json",
	             "{\"status\":\"ok\",\"message\":\"Setup mode held \\u2014 auto-switch to Standalone paused.\"}");
}

void HttpServer::sendApiFactoryReset(int sock, const std::string& body)
{
	// Require an explicit confirm token so a stray/accidental POST can't wipe the device.
	if (getFormParam(body, "confirm") != "ERASE") {
		sendResponse(sock, 400, "Bad Request", "application/json",
		             "{\"error\":\"factory reset requires confirm=ERASE\"}");
		return;
	}
	// Clear the admin credential + all sessions so the device returns to the
	// unprovisioned/open state on both ESP (NVS) and host (in-memory).
	AdminAuth::clearCredential();
	// Also drop ap_secure / ap_psk / cfgseed_gen. Clearing the seed generation is
	// deliberate: the next boot re-applies whatever the flasher wrote, so a
	// factory reset returns the board to how it was FLASHED rather than to a
	// hardcoded default the operator never chose.
	DeviceConfig::clearAll();
#if defined(POCKETDIAL_HAS_WIFI)
	nvs_handle_t nvs_handle;
	if (nvs_open("storage", NVS_READWRITE, &nvs_handle) == ESP_OK) {
		nvs_erase_key(nvs_handle, "wifi_mode");
		nvs_erase_key(nvs_handle, "wifi_ssid");
		nvs_erase_key(nvs_handle, "wifi_pass");
		nvs_erase_key(nvs_handle, "decayed");
		nvs_commit(nvs_handle);
		nvs_close(nvs_handle);
	}
	sendResponse(sock, 200, "OK", "application/json",
	             "{\"status\":\"ok\",\"message\":\"Factory reset. Rebooting to captive-portal setup...\"}");
	xTaskCreate([](void*) {
		vTaskDelay(pdMS_TO_TICKS(1000));
		esp_restart();
	}, "restart_task", 2048, NULL, 5, NULL);
#else
	sendResponse(sock, 501, "Not Implemented", "application/json",
	             "{\"error\":\"factory reset not available on desktop\"}");
#endif
}

// Registrar admission mode, as the wire spells it. Kept next to the parser below
// so the two stay in step; the JSON name is the operator-facing vocabulary from
// docs/LEARN_MODE.md, not the enumerator spelling.
static const char* registrarModeName(RequestsHandler::RegistrarMode m)
{
	switch (m)
	{
		case RequestsHandler::RegistrarMode::Learn:  return "learn";
		case RequestsHandler::RegistrarMode::Secure: return "secure";
		case RequestsHandler::RegistrarMode::Open:   break;
	}
	return "open";
}

static bool parseRegistrarMode(const std::string& s, RequestsHandler::RegistrarMode& out)
{
	if (s == "open")   { out = RequestsHandler::RegistrarMode::Open;   return true; }
	if (s == "learn")  { out = RequestsHandler::RegistrarMode::Learn;  return true; }
	if (s == "secure") { out = RequestsHandler::RegistrarMode::Secure; return true; }
	return false;
}

// Shared body for every registrar response: the current mode plus the adopted
// roster, so a mutation and a plain read return the same shape and the dashboard
// has one render path.
void HttpServer::sendApiRegistrar(int sock)
{
	RequestsHandler* handler = _handler.load(std::memory_order_acquire);
	if (!handler)
	{
		// The dashboard can be up before the SIP engine is attached (an
		// unprovisioned device holds SIP dark until a credential exists), so this
		// is a normal transient state, not an error. Say so explicitly rather than
		// reporting a mode we cannot actually read.
		sendResponse(sock, 200, "OK", "application/json",
		             "{\"attached\":false,\"mode\":\"unknown\",\"devices\":[]}");
		return;
	}

	std::ostringstream json;
	json << "{\"attached\":true,\"mode\":\""
	     << registrarModeName(handler->getRegistrarMode())
	     << "\",\"devices\":[";

	bool first = true;
	for (const auto& d : handler->getAdoptedDevices())
	{
		if (!first)
		{
			json << ",";
		}
		first = false;
		json << "{\"mac\":\"" << jsonEscape(d.mac)
		     << "\",\"extension\":\"" << jsonEscape(d.extension)
		     << "\",\"state\":\""
		     << ((d.state == RequestsHandler::DeviceState::Secured) ? "secured" : "learned")
		     << "\",\"online\":" << (d.online ? "true" : "false")
		     << "}";
	}
	json << "]}";
	sendResponse(sock, 200, "OK", "application/json", json.str());
}

void HttpServer::sendApiRegistrarSet(int sock, const std::string& body)
{
	RequestsHandler::RegistrarMode mode;
	if (!parseRegistrarMode(getFormParam(body, "mode"), mode))
	{
		sendResponse(sock, 400, "Bad Request", "application/json",
		             "{\"error\":\"mode must be one of: open, learn, secure\"}");
		return;
	}

	RequestsHandler* handler = _handler.load(std::memory_order_acquire);
	if (!handler)
	{
		sendResponse(sock, 503, "Service Unavailable", "application/json",
		             "{\"error\":\"SIP engine not attached yet\"}");
		return;
	}

	// Guard the one transition that can take the whole phone system down in a
	// single click. Switching to `secure` makes every REGISTER digest-challenged;
	// a device that has never been through Learn mode has no secured extensions,
	// so EVERY phone would fail to register and the operator would have no working
	// handset left to notice with. Requiring an explicit confirm mirrors the
	// confirm=ERASE convention already used by /api/factory-reset.
	if (mode == RequestsHandler::RegistrarMode::Secure)
	{
		size_t secured = 0;
		for (const auto& d : handler->getAdoptedDevices())
		{
			if (d.state == RequestsHandler::DeviceState::Secured)
			{
				++secured;
			}
		}
		const std::string confirm = getFormParam(body, "confirm");
		if (secured == 0 && confirm != "LOCKOUT")
		{
			sendResponse(sock, 409, "Conflict", "application/json",
			             "{\"error\":\"no extensions are secured yet; switching to secure now would "
			             "reject every phone. Adopt them in learn mode first, or resend with "
			             "confirm=LOCKOUT to override.\"}");
			return;
		}
	}

	handler->setRegistrarMode(mode);
	sendApiRegistrar(sock);
}

void HttpServer::sendApiRegistrarDevice(int sock, const std::string& body)
{
	const std::string action = getFormParam(body, "action");
	const std::string target = getFormParam(body, "target");

	if (target.empty())
	{
		sendResponse(sock, 400, "Bad Request", "application/json",
		             "{\"error\":\"missing target (a 12-hex MAC or an extension)\"}");
		return;
	}

	RequestsHandler* handler = _handler.load(std::memory_order_acquire);
	if (!handler)
	{
		sendResponse(sock, 503, "Service Unavailable", "application/json",
		             "{\"error\":\"SIP engine not attached yet\"}");
		return;
	}

	bool ok = false;
	if (action == "secure")
	{
		ok = handler->secureDevice(target);
	}
	else if (action == "forget")
	{
		ok = handler->forgetDevice(target);
	}
	else
	{
		sendResponse(sock, 400, "Bad Request", "application/json",
		             "{\"error\":\"action must be one of: secure, forget\"}");
		return;
	}

	if (!ok)
	{
		sendResponse(sock, 404, "Not Found", "application/json",
		             "{\"error\":\"no adopted device matches that MAC or extension\"}");
		return;
	}

	sendApiRegistrar(sock);
}

void HttpServer::sendApiApSecurity(int sock)
{
	// The passphrase is returned in clear to an authenticated admin on purpose.
	// On the headless eth/wifi builds there is no screen, so this response is the
	// only way to learn it — and it is exactly what the operator needs in hand in
	// order to re-associate the phones after switching WPA2 on.
	std::ostringstream json;
	json << "{\"secure\":" << (DeviceConfig::isApSecure() ? "true" : "false")
	     << ",\"psk\":\"" << jsonEscape(DeviceConfig::getApPsk()) << "\"}";
	sendResponse(sock, 200, "OK", "application/json", json.str());
}

void HttpServer::sendApiApSecuritySet(int sock, const std::string& body)
{
	const std::string secure = getFormParam(body, "secure");
	const std::string psk    = getFormParam(body, "psk");
	const std::string regen  = getFormParam(body, "regenerate");

	// Validate before changing anything, so a rejected passphrase cannot leave the
	// AP half-configured (secure switched on with a passphrase esp_wifi refuses,
	// which would bring the AP up open or not at all on the next boot).
	if (!psk.empty() && !DeviceConfig::setApPsk(psk))
	{
		sendResponse(sock, 400, "Bad Request", "application/json",
		             "{\"error\":\"passphrase must be 8-63 printable ASCII characters\"}");
		return;
	}
	if (regen == "1" || regen == "true")
	{
		DeviceConfig::regenerateApPsk();
	}
	if (!secure.empty())
	{
		DeviceConfig::setApSecure(secure == "1" || secure == "true");
	}

	// The radio is deliberately NOT restarted here. Dropping the AP out from under
	// the client that just made this request would lose the response — including
	// the passphrase it still has to display — and on a device carrying live calls
	// it would tear down SIP and RTP with it. The change takes effect at the next
	// AP bringup; the dashboard says so.
	sendApiApSecurity(sock);
}

void HttpServer::sendApiAdminStatus(int sock, const HttpRequest& req)
{
	bool provisioned = AdminAuth::isProvisioned();
	bool authenticated = isAuthed(req);
	std::ostringstream json;
	json << "{\"provisioned\":" << (provisioned ? "true" : "false")
	     << ",\"authenticated\":" << (authenticated ? "true" : "false") << "}";
	sendResponse(sock, 200, "OK", "application/json", json.str());
}

void HttpServer::sendApiAdminSetPin(int sock, const HttpRequest& req)
{
	// First-run onboarding: setting a PIN is allowed only when the device is not
	// yet provisioned, OR when the caller already holds a valid session (changing
	// an existing PIN). This prevents an unauthenticated AP peer from overwriting
	// a provisioned admin PIN.
	if (AdminAuth::isProvisioned() && !isAuthed(req))
	{
		sendResponse(sock, 401, "Unauthorized", "application/json",
		             "{\"error\":\"authentication required to change PIN\"}");
		return;
	}

	std::string pin = getFormParam(req.body, "pin");
	if (pin.size() < AdminAuth::kMinPinLength)
	{
		sendResponse(sock, 400, "Bad Request", "application/json",
		             "{\"error\":\"PIN must be at least 4 characters\"}");
		return;
	}

	// The DTMF HTTP-open star-code is *4887 (no '#'); onDtmfInfo fires it the
	// instant the accumulated sequence equals "*4887", before the *PIN#code
	// parser runs. A PIN beginning with those four digits would be shadowed —
	// the star-code opens HTTP mid-entry and clears the accumulator, so the
	// admin's *PIN#code command never completes. Reserve the prefix at the one
	// choke point where PINs are set. (Does not retroactively fix a device
	// already provisioned with a 4887-prefixed PIN; only new/changed PINs.)
	if (pin.rfind("4887", 0) == 0)
	{
		sendResponse(sock, 400, "Bad Request", "application/json",
		             "{\"error\":\"PIN must not begin with 4887 (reserved for the HTTP-open star code)\"}");
		return;
	}

	if (!AdminAuth::setPin(pin))
	{
		sendResponse(sock, 500, "Internal Server Error", "application/json",
		             "{\"error\":\"failed to store PIN\"}");
		return;
	}

	// PLAN_ADMIN_HTTP_ONLY.md: setting a PIN flips AdminAuth::isProvisioned() to
	// true, which is exactly the condition that puts the accept-loop's
	// dark-by-default gate into effect. Grant the same TTL window a DTMF trigger
	// would so the operator who just provisioned (or is changing an existing
	// PIN, same call path) doesn't lose HTTP access before finishing onboarding.
	if (RequestsHandler* handler = _handler.load(std::memory_order_acquire))
	{
		handler->grantAdminHttpGraceWindow();
	}

	sendResponse(sock, 200, "OK", "application/json",
	             "{\"status\":\"ok\",\"provisioned\":true}");
}

void HttpServer::sendApiAdminLogin(int sock, const HttpRequest& req)
{
	if (!AdminAuth::isProvisioned())
	{
		// Nothing to log in to yet — direct the client to set a PIN first.
		sendResponse(sock, 409, "Conflict", "application/json",
		             "{\"error\":\"no admin PIN set; call /api/admin/set-pin first\"}");
		return;
	}

	// Reject while locked out before doing any hashing work. Accounting is keyed
	// on the peer address so one guessing client cannot lock the real admin out
	// of new logins (docs/THREAT_MODEL.md D-3). A spoofed source only ever buys
	// the spoofer their own fresh bucket — the key is for fairness, not trust.
	if (AdminAuth::isLockedOut(req.clientIp))
	{
		sendResponse(sock, 429, "Too Many Requests", "application/json",
		             "{\"error\":\"too many failed attempts; try again later\"}");
		return;
	}

	std::string pin = getFormParam(req.body, "pin");
	if (!AdminAuth::verifyPin(pin, req.clientIp))
	{
		// verifyPin may have just engaged the lockout on this attempt.
		if (AdminAuth::isLockedOut(req.clientIp))
		{
			sendResponse(sock, 429, "Too Many Requests", "application/json",
			             "{\"error\":\"too many failed attempts; try again later\"}");
		}
		else
		{
			sendResponse(sock, 401, "Unauthorized", "application/json",
			             "{\"error\":\"invalid PIN\"}");
		}
		return;
	}

	std::string token = AdminAuth::createSession();
	if (token.empty())
	{
		sendResponse(sock, 500, "Internal Server Error", "application/json",
		             "{\"error\":\"failed to create session\"}");
		return;
	}

	// HttpOnly: not readable from JS (mitigates XSS token theft).
	// SameSite=Strict: the browser won't attach it to cross-site requests
	// (defense in depth alongside the same-origin check). No Secure flag: the
	// dashboard is plain HTTP on a LAN appliance (see docs/THREAT_MODEL.md).
	std::string cookie = "Set-Cookie: pd_session=" + token +
	                     "; HttpOnly; Path=/; SameSite=Strict";

	// Hand the page its CSRF token here as well as in the rendered document, so a
	// login performed with fetch() can start making mutating calls immediately
	// instead of needing a full reload to pick the token up.
	std::ostringstream json;
	json << "{\"status\":\"ok\",\"authenticated\":true,\"csrf\":\""
	     << jsonEscape(AdminAuth::sessionCsrf(token)) << "\"}";
	sendResponseWithHeader(sock, 200, "OK", "application/json", json.str(), cookie);
}

void HttpServer::sendApiAdminLogout(int sock, const HttpRequest& req)
{
	std::string token = cookieValue(req, "pd_session");
	if (!token.empty())
	{
		AdminAuth::destroySession(token);
	}
	// Expire the cookie on the client side too (Max-Age=0).
	std::string cookie = "Set-Cookie: pd_session=; HttpOnly; Path=/; SameSite=Strict; Max-Age=0";
	sendResponseWithHeader(sock, 200, "OK", "application/json",
	                       "{\"status\":\"ok\"}", cookie);
}

void HttpServer::sendApiAdminKeepAlive(int sock, const HttpRequest& req)
{
	if (!isAuthed(req))
	{
		sendResponse(sock, 401, "Unauthorized", "application/json",
		             "{\"error\":\"authentication required\"}");
		return;
	}
	RequestsHandler* handler = _handler.load(std::memory_order_acquire);
	if (!handler)
	{
		sendResponse(sock, 503, "Service Unavailable", "application/json",
		             "{\"error\":\"registrar not ready\"}");
		return;
	}
	handler->extendAdminHttpWindowOneHour();
	sendResponse(sock, 200, "OK", "application/json",
	             "{\"status\":\"ok\",\"extendedSeconds\":3600}");
}

bool HttpServer::streamBody(int sock, const char* prefix, size_t prefixLen,
                            size_t contentLength,
                            const std::function<bool(const uint8_t*, size_t)>& chunkSink)
{
	size_t consumed = 0;

	// 1) Feed any body bytes that already arrived in the header recv.
	if (prefixLen > 0)
	{
		size_t take = (prefixLen <= contentLength) ? prefixLen : contentLength;
		if (take > 0 && !chunkSink(reinterpret_cast<const uint8_t*>(prefix), take))
			return false;
		consumed += take;
	}

	// 2) Drain the rest off the socket in fixed 4 KB chunks. Heap-allocated
	//    (the accept-loop thread has a ~3 KB pthread stack on ESP — see
	//    handleClient — so a stack buffer would overflow). The per-socket
	//    SO_RCVTIMEO (5 s, set in handleClient) bounds a stalled sender.
	std::vector<uint8_t> chunk(4096);
	while (consumed < contentLength)
	{
		size_t want = contentLength - consumed;
		if (want > chunk.size()) want = chunk.size();
#if defined _WIN32 || defined _WIN64
		int n = recv(sock, reinterpret_cast<char*>(chunk.data()), static_cast<int>(want), 0);
#else
		int n = static_cast<int>(recv(sock, chunk.data(), want, 0));
#endif
		if (n <= 0)
			return false; // peer closed early or timed out → incomplete body
		if (!chunkSink(chunk.data(), static_cast<size_t>(n)))
			return false;
		consumed += static_cast<size_t>(n);
	}
	return consumed == contentLength;
}

void HttpServer::handleOtaUpload(int sock, const std::string& alreadyRead,
                                 size_t bodyStart, size_t contentLength)
{
	const char*  prefix    = (bodyStart <= alreadyRead.size())
	                             ? alreadyRead.data() + bodyStart : nullptr;
	const size_t prefixLen = (bodyStart <= alreadyRead.size())
	                             ? alreadyRead.size() - bodyStart : 0;

#if defined(ESP_PLATFORM)
	// Device path: stream the body straight into the inactive OTA slot.
	OtaUpdater ota;
	if (!ota.begin(contentLength))
	{
		// Drain the body so the client's send completes and we can reply cleanly
		// instead of resetting the connection mid-upload.
		streamBody(sock, prefix, prefixLen, contentLength,
		           [](const uint8_t*, size_t) { return true; });
		sendResponse(sock, 500, "Internal Server Error", "application/json",
		             "{\"error\":\"ota begin failed: " + jsonEscape(ota.lastError()) + "\"}");
		return;
	}

	bool writeOk = streamBody(sock, prefix, prefixLen, contentLength,
		[&ota](const uint8_t* p, size_t n) { return ota.write(p, n); });

	if (!writeOk)
	{
		ota.abort();
		sendResponse(sock, 400, "Bad Request", "application/json",
		             "{\"error\":\"incomplete upload or flash write failed: "
		             + jsonEscape(ota.lastError()) + "\"}");
		return;
	}

	if (!ota.end())
	{
		// end() already released the handle; report the validation error.
		sendResponse(sock, 422, "Unprocessable Entity", "application/json",
		             "{\"error\":\"image rejected: " + jsonEscape(ota.lastError()) + "\"}");
		return;
	}

	if (!ota.activate())
	{
		sendResponse(sock, 500, "Internal Server Error", "application/json",
		             "{\"error\":\"activate failed: " + jsonEscape(ota.lastError()) + "\"}");
		return;
	}

	std::ostringstream json;
	json << "{\"status\":\"ok\",\"bytes\":" << ota.bytesWritten()
	     << ",\"rebootRequired\":true"
	     << ",\"nextPartition\":\"" << jsonEscape(OtaUpdater::nextUpdatePartitionLabel()) << "\""
	     << ",\"message\":\"image staged; POST /api/ota/reboot to boot it\"}";
	sendResponse(sock, 200, "OK", "application/json", json.str());
#else
	// Host stub: real flashing is impossible off-device. Drain the body (bounded
	// by Content-Length + the 5 s socket timeout) so curl completes cleanly, then
	// return 501. We do NOT simulate success — a 200 here could be mistaken for a
	// real update in tooling/CI.
	(void)contentLength;
	streamBody(sock, prefix, prefixLen, contentLength,
	           [](const uint8_t*, size_t) { return true; });
	sendResponse(sock, 501, "Not Implemented", "application/json",
	             "{\"error\":\"OTA only available on device\"}");
#endif
}

void HttpServer::sendApiOtaStatus(int sock)
{
	std::ostringstream json;
	json << "{";
	json << "\"running\":\""  << jsonEscape(OtaUpdater::runningPartitionLabel())    << "\",";
	json << "\"boot\":\""     << jsonEscape(OtaUpdater::bootPartitionLabel())       << "\",";
	json << "\"next\":\""     << jsonEscape(OtaUpdater::nextUpdatePartitionLabel()) << "\",";
	json << "\"pendingVerify\":" << (OtaUpdater::isPendingVerify() ? "true" : "false") << ",";
#if defined(ESP_PLATFORM)
	json << "\"otaSupported\":true,";
#else
	json << "\"otaSupported\":false,";
#endif
	json << "\"error\":\"\"";
	json << "}";
	sendResponse(sock, 200, "OK", "application/json", json.str());
}

void HttpServer::sendApiOtaReboot(int sock)
{
#if defined(ESP_PLATFORM)
	// Only reboot if there is actually a staged image to boot into; otherwise a
	// stray POST would needlessly bounce the device.
	if (OtaUpdater::bootPartitionLabel() == OtaUpdater::runningPartitionLabel())
	{
		sendResponse(sock, 409, "Conflict", "application/json",
		             "{\"error\":\"no pending OTA image to boot into\"}");
		return;
	}

	sendResponse(sock, 200, "OK", "application/json",
	             "{\"status\":\"ok\",\"message\":\"rebooting into the new image...\"}");

	// Defer the restart so the HTTP response flushes first (mirrors the WiFi
	// connect/mode endpoints' delayed-restart pattern).
	xTaskCreate([](void*) {
		vTaskDelay(pdMS_TO_TICKS(1000));
		esp_restart();
	}, "ota_reboot", 2048, NULL, 5, NULL);
#else
	// Host stub: never actually exit the process (the smoke-test harness keeps
	// running). Report a simulated success.
	sendResponse(sock, 200, "OK", "application/json",
	             "{\"status\":\"ok\",\"simulated\":true,"
	             "\"message\":\"reboot is a no-op on the desktop build\"}");
#endif
}

void HttpServer::sendRedirect(int sock, const std::string& location)
{
	// Routed through sendResponseWithHeader rather than writing the socket
	// directly. This used to hand-roll the response, which meant the captive-
	// portal redirect was the one reply that carried NONE of the security
	// headers every other response gets, and the only one whose write was a
	// single ::send() with no short-write retry.
	sendResponseWithHeader(sock, 302, "Found", "text/plain", "",
	                       "Location: " + location);
}
