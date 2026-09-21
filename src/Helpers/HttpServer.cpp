// HttpServer.cpp: Issues #23 and #28 resolved.
#include "HttpServer.hpp"
#include "RequestsHandler.hpp"
#include "DialPlan.hpp"          // Issue #69: dial-rule validation shared with setDialRule
#include "ServiceExtensions.hpp" // Issue #202: reserved engine-owned pseudo-AORs
#include "TelephonyApiConfig.hpp"
#include "DidMapping.hpp"
#include "CallDetailRecord.hpp"
#include "CdrArchive.hpp"  // Issue #194 Stage 1: SD CDR archive wipe on factory reset
#include "AdminAuth.hpp"
#include "DeviceConfig.hpp"
#include "OtaUpdater.hpp"
#include "ProvisioningConfig.hpp"
#include "ArpLookup.hpp"
#include "index_html.h"
#include "IPHelper.hpp"
#include "UrlEncode.hpp"
#include "Syslog.hpp"        // single source of truth for urlDecode (see below)
// Issue #159 (SMTP client): SmtpDialogue is the pure protocol engine,
// SmtpClient the real transport + bounded send queue, EmailConfigStore the
// persisted "pbxcfg" config, GoogleServiceAuth the Workspace service-account
// XOAUTH2 token path.
#include "SmtpDialogue.hpp"
#include "SmtpClient.hpp"
#include "EmailConfigStore.hpp"
#include "GoogleServiceAuth.hpp"
// Issue #186 (config export/import): the digest-secret and mDNS/park-timeout
// readers below need these two subsystems' EXISTING public accessors, exactly
// like the includes above pull in DialPlan/TelephonyApiConfig/DidMapping/etc
// for the other sendApi* handlers. Neither is modified -- see sendApiConfigExport's
// comment on the HA1-export/no-import asymmetry this implies.
#include "SipSecretStore.hpp"
#include "PoolConfig.hpp"    // POCKETDIAL_PARK_TIMEOUT_SEC (informational export field)
#include "JsonReader.hpp"    // strict, dependency-free JSON reader for /api/config/import
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <iostream>
#include <chrono>
#include <algorithm>
#include <vector>
#include <set>

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
// Issue #185: heap_caps_get_minimum_free_size(MALLOC_CAP_SPIRAM) for
// sendApiStatus's minFreeHeapSpiram field.
#include "esp_heap_caps.h"
// Issue #366: esp_pthread_set_cfg() to size the per-connection thread stack
// independently of CONFIG_PTHREAD_TASK_STACK_SIZE_DEFAULT.
#include "esp_pthread.h"
#endif

// Forward declarations for the file-local form/URL helpers (defined lower down).
// sendApiDnd() and sendApiKill() use getFormParam() but are defined earlier in
// this TU — this declaration is what lets them, so no reordering is needed.
static std::string getFormParam(const std::string& body, const std::string& key);

#if defined(PD_ETH_HAS_SD)
// Defined in main/esp_main_eth.cpp, which owns the card. Declared rather than
// pulled in through a header because that file is a transport main, not a module.
extern "C" bool     pd_sd_mounted(void);
extern "C" uint64_t pd_sd_capacity_mb(void);
#endif

// Path-shape parsers for the two PUT/POST telephony-config routes, which (unlike
// every other route in this file) carry a slot index as a URL segment rather
// than a form param. Mirrors isProvisioningConfigPath's style: pure string-shape
// checks, no registry access, used directly in the route table's if/else chain
// below (each defined further down, alongside the handlers that use them).
static bool parseTelephonyConfigSlotPath(const std::string& path, size_t& slotIdx);
static bool parseTelephonyConfigActivatePath(const std::string& path, size_t& slotIdx);
static bool parseTelephonyConfigTestPath(const std::string& path, size_t& slotIdx);

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

	// The dashboard listens immediately regardless of provisioning state.
	// requireAdmin()'s per-route session/credential check is the actual admin
	// gate; the socket itself always accepts connections.
	if (!openListenSocket())
	{
		throw std::runtime_error("HttpServer: failed to open listen socket on port " + std::to_string(_port));
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
#if defined(ESP_PLATFORM)
	// Issue #366. esp_pthread_set_cfg() applies to threads created BY THE
	// CALLING THREAD, and this one creates nothing except the per-connection
	// handlers below -- so setting it once here covers all of them and leaves
	// every other std::thread in the firmware on the 8192 Kconfig default.
	// Changing CONFIG_PTHREAD_TASK_STACK_SIZE_DEFAULT instead would have
	// re-sized threads this issue never measured.
	//
	// A failure here is not fatal: the threads simply keep the old default and
	// we are back to the pre-fix behaviour, which is a dropped connection under
	// fragmentation rather than a crash. Log it so a silent regression to 8192
	// is visible in the boot log instead of being invisible until the board
	// starts refusing connections again.
	{
		esp_pthread_cfg_t cfg = esp_pthread_get_default_config();
		cfg.stack_size  = kHttpConnStackBytes;
		cfg.thread_name = "http_conn";
		const esp_err_t cfgErr = esp_pthread_set_cfg(&cfg);
		if (cfgErr != ESP_OK)
		{
			std::cerr << "[HttpServer] esp_pthread_set_cfg failed (" << esp_err_to_name(cfgErr)
				<< ") — connection threads keep the "
				<< CONFIG_PTHREAD_TASK_STACK_SIZE_DEFAULT << "-byte default\n";
		}
	}
#endif

	while (_running)
	{
		if (_listenSock < 0)
		{
			// Only reachable if the listen socket was closed out from under us
			// (it never is, today) — retry rather than spin.
			if (!openListenSocket())
			{
				std::this_thread::sleep_for(std::chrono::milliseconds(250));
				continue;
			}
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
				recordConnStackHwm();
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
			    (reqLine.find(" /api/ota/upload ") != std::string::npos ||
			     reqLine.find(" /api/moh/upload ") != std::string::npos))
			{
				// The music-on-hold clip takes the SAME streaming treatment, for the
				// same reason: it is ~800 KB of audio and must not flow through the
				// 16 KB-capped buffered path below. Without this route there is no
				// way to get a clip onto the card at all short of physically pulling
				// it, because the firmware has no other filesystem writer.
				const bool isMoh =
					reqLine.find(" /api/moh/upload ") != std::string::npos;
				// Parse just the header block (parseRequest tolerates a truncated
				// body) to get method/path/origin/host/cookie for the auth gate.
				HttpRequest otaReq = parseRequest(raw.substr(0, hdrEnd + 4));
				otaReq.clientIp = peerIp;

				// Same gate as every other mutating endpoint, PLUS issue #173's
				// owner-only floor for OTA upload specifically (MoH clip upload
				// stays sysop-level — it is audio, not firmware). Flashing
				// firmware is the most consequential thing this server does, so
				// it gets the CSRF check too — the dashboard's upload path sends
				// the token.
				const AdminAuth::Role otaMinRole =
					isMoh ? AdminAuth::Role::Sysop : AdminAuth::Role::Owner;
				if (!requireAdmin(clientSock, otaReq, true, otaMinRole))
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
					             isMoh ? "{\"error\":\"clip upload requires a non-zero Content-Length\"}"
					                   : "{\"error\":\"OTA upload requires a non-zero Content-Length\"}");
					closeSocket(clientSock);
					return;
				}

				if (isMoh)
				{
					handleMohUpload(clientSock, raw, hdrEnd + 4, otaLen);
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
	// Out-param for the two telephony-config routes below, whose slot index is
	// a URL path segment rather than a form param (see parseTelephonyConfigSlotPath).
	size_t telSlotIdx = 0;

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
		// Issue #35, #234: GET /config/<mac>.cfg, /config/cfg<mac>.xml, etc. —
		// a phone's own auto-provisioning fetch, so intentionally NOT
		// session-gated (a booting phone has no session cookie to present).
		// The MAC/path itself is the credential: it's not guessable (2^48
		// space) and only served for a MAC already in the adopted-device
		// registry, or a recognized master/bootstrap file.
		sendProvisioningResponse(clientSock, req);
	}
	else if (req.method == "GET" && req.path == "/api/status")
	{
		// Issue #207: stays reachable unauthenticated -- E-2's justification is real,
		// the dashboard genuinely needs this to render before login -- but the
		// EXTENSION ROSTER is withheld from an unauthenticated caller.
		//
		// E-2 justifies this endpoint by what the login form needs. What it returned
		// included every registered extension number with its handset's IP and port,
		// which is not that: it is a target list for the SIP INFO spoofing described
		// in E-4 of the same document, which notes there is no source-IP check on the
		// DTMF admin parser and that a From header is free text. E-4's mitigation is
		// "set a long PIN"; this endpoint was handing over the admin extension number
		// to put in that From, for free.
		//
		// requireAdmin's third argument is the CSRF requirement, and passing false
		// here would reject an unauthenticated caller outright -- so ask without
		// enforcing, and let sendApiStatus decide what to include.
		sendApiStatus(clientSock, hasValidAdminSession(req));
	}
	else if (req.method == "GET" && req.path == "/metrics")
	{
		// Issue #184: deliberately ungated, in the same read-only class as
		// /api/status directly above — see sendApiMetrics for the full
		// justification against docs/THREAT_MODEL.md §4 E-2.
		sendApiMetrics(clientSock);
	}
	else if (req.method == "POST" && req.path == "/api/kill")
	{
		if (requireAdmin(clientSock, req, true))
		{
			sendApiKill(clientSock, req.body);
		}
	}
	else if (req.method == "GET" && req.path == "/api/syslog")
	{
		// Gated. The collector address is infrastructure detail, and #207 was filed
		// about a read endpoint that had been ungated by analogy rather than by
		// analysis -- so this takes the conservative side deliberately.
		//
		// Written as the fall-through form deliberately: `if (!requireAdmin(...))
		// return;` (both this route and the POST one just below, until this fix)
		// jumps straight over handleClient()'s single closeSocket() at the bottom
		// of the route chain and leaks a socket on every rejected request -- the
		// exact #207/#215 pattern, reintroduced here by 9356d2d after #215 had
		// already fixed it on /api/moh's three routes. See
		// docs/THREAT_MODEL.md D-5. (Independently caught and fixed the same way
		// by both #227 and #230 -- this comment is whichever landed second.)
		if (requireAdmin(clientSock, req, false))
		{
			sendApiSyslogStatus(clientSock);
		}
	}
	else if (req.method == "POST" && req.path == "/api/syslog")
	{
		if (requireAdmin(clientSock, req, true))
		{
			sendApiSyslogSet(clientSock, req.body);
		}
	}
	else if (req.method == "GET" && req.path == "/setup/email")
	{
		// Ungated shell, same class as "/" -- see sendEmailSetupHtml's
		// declaration comment and docs/THREAT_MODEL.md §4 E-2.
		sendEmailSetupHtml(clientSock, req);
	}
	else if (req.method == "GET" && req.path == "/api/email")
	{
		// Gated: even redacted, this discloses host/user/from -- infrastructure
		// detail, same conservative call as /api/syslog just above.
		if (requireAdmin(clientSock, req, false))
		{
			sendApiEmailConfig(clientSock);
		}
	}
	else if (req.method == "POST" && req.path == "/api/email")
	{
		if (requireAdmin(clientSock, req, true))
		{
			sendApiEmailConfigSet(clientSock, req.body);
		}
	}
	else if (req.method == "POST" && req.path == "/api/email/test")
	{
		// Places a real outbound send -- same mutating-action gate as
		// /api/telephony-config/<slot>/test above.
		if (requireAdmin(clientSock, req, true))
		{
			sendApiEmailTest(clientSock, req.body);
		}
	}
	else if (req.method == "GET" && req.path == "/api/moh")
	{
		// Music-on-hold status. Gated: it reveals what is configured, and the
		// dashboard already holds a session by the time it renders this panel.
		if (requireAdmin(clientSock, req, false))
		{
			sendApiMohStatus(clientSock);
		}
	}
	else if (req.method == "POST" && req.path == "/api/moh/preview")
	{
		// Ring an extension and play the clip to it. Mutating (it originates a
		// call), so CSRF is required like every other POST.
		if (requireAdmin(clientSock, req, true))
		{
			sendApiMohPreview(clientSock, req.body);
		}
	}
	else if (req.method == "POST" && req.path == "/api/moh/preview/stop")
	{
		if (requireAdmin(clientSock, req, true))
		{
			sendApiMohPreviewStop(clientSock);
		}
	}
	else if (req.method == "GET" && req.path == "/api/cdr")
	{
		// Issue #207: gated, same as /api/pcap and /api/trace.
		//
		// This was ungated by analogy -- "read-only, like /api/status" -- and the
		// analogy does not hold. THREAT_MODEL.md section 4 E-2 enumerates the reads
		// that are intentionally unauthenticated and gives the reason: the dashboard
		// needs them to render the LOGIN FORM. A login form does not need call
		// history. /api/cdr appears in neither E-2's ungated list nor its list of
		// sensitive gated reads; it was never assessed at all.
		//
		// Call metadata -- who called whom, when, for how long -- is close to the
		// most sensitive thing a PBX holds. Verified on the bench that any host on
		// the LAN could read the full ring with no credentials.
		if (requireAdmin(clientSock, req, false))
		{
			sendApiCdr(clientSock);
		}
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
	else if (req.method == "POST" && req.path == "/api/voicemail")
	{
		// Mutating: same gate as /api/dnd (same-origin + auth once provisioned).
		if (requireAdmin(clientSock, req, true))
		{
			sendApiVoicemail(clientSock, req.body);
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
	else if (req.method == "GET" && req.path == "/api/telephony-config")
	{
		// Read-gated like /api/registrar (credential-adjacent config, not
		// public dashboard data like /api/status's DND/forward/group arrays).
		if (requireAdmin(clientSock, req, false))
		{
			sendApiTelephonyConfigList(clientSock);
		}
	}
	else if (req.method == "PUT" && parseTelephonyConfigSlotPath(req.path, telSlotIdx))
	{
		if (requireAdmin(clientSock, req, true))
		{
			sendApiTelephonyConfigSet(clientSock, telSlotIdx, req.body);
		}
	}
	else if (req.method == "POST" && parseTelephonyConfigActivatePath(req.path, telSlotIdx))
	{
		if (requireAdmin(clientSock, req, true))
		{
			sendApiTelephonyConfigActivate(clientSock, telSlotIdx);
		}
	}
	else if (req.method == "POST" && parseTelephonyConfigTestPath(req.path, telSlotIdx))
	{
		// Places (and immediately drops) a real outbound call through the
		// active anchor client -- same mutating-action gate as activate/PUT/DELETE.
		if (requireAdmin(clientSock, req, true))
		{
			sendApiTelephonyConfigTest(clientSock, telSlotIdx);
		}
	}
	else if (req.method == "DELETE" && parseTelephonyConfigSlotPath(req.path, telSlotIdx))
	{
		// Same gate as the sibling PUT/activate routes above -- an operator
		// needs a way to remove a stored secret without a full factory reset.
		if (requireAdmin(clientSock, req, true))
		{
			sendApiTelephonyConfigDelete(clientSock, telSlotIdx);
		}
	}
	else if (req.method == "GET" && req.path == "/api/e911-config")
	{
		// Read gate matches the other config surfaces: nothing here is secret.
		if (requireAdmin(clientSock, req, false))
		{
			sendApiE911Get(clientSock);
		}
	}
	else if (req.method == "PUT" && req.path == "/api/e911-config")
	{
		// Sysop to WRITE: this decides who finds out when somebody dials 911.
		if (requireAdmin(clientSock, req, true))
		{
			sendApiE911Set(clientSock, req.body);
		}
	}
	else if (req.method == "GET" && req.path == "/api/sbc-mode")
	{
		// Read gate matches the other config surfaces: nothing here is secret.
		if (requireAdmin(clientSock, req, false))
		{
			sendApiSbcModeGet(clientSock);
		}
	}
	else if (req.method == "PUT" && req.path == "/api/sbc-mode")
	{
		// Mutating: same gate as /api/dialplan and /api/telephony-config's
		// activate route -- this decides where EVERY call goes.
		if (requireAdmin(clientSock, req, true))
		{
			sendApiSbcModeSet(clientSock, req.body);
		}
	}
	else if (req.method == "GET" && req.path == "/api/did-mapping")
	{
		// Same read gate as /api/telephony-config above.
		if (requireAdmin(clientSock, req, false))
		{
			sendApiDidMappingList(clientSock);
		}
	}
	else if (req.method == "PUT" && req.path == "/api/did-mapping")
	{
		if (requireAdmin(clientSock, req, true))
		{
			sendApiDidMappingSet(clientSock, req.body);
		}
	}
	else if (req.method == "DELETE" && req.path == "/api/did-mapping")
	{
		if (requireAdmin(clientSock, req, true))
		{
			sendApiDidMappingDelete(clientSock, req.body);
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
		// to Standalone out from under the user. It moves device state on a
		// POST, so it takes the standard gate like every other mutating route:
		// log in with the default credential first (documented at first boot),
		// same as WiFi setup itself (/api/wifi/connect, /api/wifi/mode_ap)
		// just below.
		if (requireAdmin(clientSock, req, true))
		{
			sendApiConfiguring(clientSock);
		}
	}
	else if (req.method == "POST" && req.path == "/api/factory-reset")
	{
		// Issue #173: owner-only (one of the three named owner-gated actions).
		if (requireAdmin(clientSock, req, true, AdminAuth::Role::Owner))
		{
			sendApiFactoryReset(clientSock, req.body);
		}
	}
	else if (req.method == "GET" && req.path == "/api/config/export")
	{
		// Plaintext-only export. Read, but genuinely sensitive (digest secrets,
		// dial plan, MAC bindings) -- sysop-gated, not public like /api/status.
		if (requireAdmin(clientSock, req, false))
		{
			sendApiConfigExport(clientSock, /*withSecrets=*/false, "");
		}
	}
	else if (req.method == "POST" && req.path == "/api/config/export")
	{
		// A non-empty `password` selects the encrypted secretsEnc block, and
		// THAT is the one owner-only half of this endpoint (#173: "config
		// export with secrets"). An empty/absent password on the POST is
		// treated exactly like the GET (sysop-level, plaintext only) rather
		// than rejected outright, so the dashboard can use one form for both.
		const std::string password = getFormParam(req.body, "password");
		const bool withSecrets = !password.empty();
		if (requireAdmin(clientSock, req, true,
			withSecrets ? AdminAuth::Role::Owner : AdminAuth::Role::Sysop))
		{
			sendApiConfigExport(clientSock, withSecrets, password);
		}
	}
	else if (req.method == "POST" && req.path == "/api/config/import")
	{
		// Sysop-level: #173 lists factory reset / export-with-secrets / OTA
		// upload as the three owner-only actions, and restoring config is not
		// one of them -- it gets its own confirm-before-overwrite interlock
		// instead (checked inside the handler), matching "sysop gets add/
		// change with a confirm-before-overwrite interlock".
		if (requireAdmin(clientSock, req, true))
		{
			sendApiConfigImport(clientSock, req.body);
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
		// Read-only: tells the dashboard whether to show the login form.
		sendApiAdminStatus(clientSock, req);
	}
	else if (req.method == "POST" && req.path == "/api/admin/set-credential")
	{
		// Always needs a session + CSRF token — including during forced initial
		// setup, since that's reached by first logging in with the default
		// credential (requireAdmin's setup_required gate exempts this one path).
		if (requireAdmin(clientSock, req, true))
		{
			sendApiAdminSetCredential(clientSock, req);
		}
	}
	else if (req.method == "POST" && req.path == "/api/admin/set-owner-credential")
	{
		// Issue #173: owner-gated (sessionSatisfiesRole's no-owner-yet fallback
		// is what lets a sysop session BOOTSTRAP the first owner account here;
		// once one exists, only an owner session may replace it).
		if (requireAdmin(clientSock, req, true, AdminAuth::Role::Owner))
		{
			sendApiAdminSetOwnerCredential(clientSock, req);
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
				    hName == "x-csrf" || hName == "user-agent") {
					size_t valStart = colon + 1;
					while (valStart < line.size() && std::isspace(static_cast<unsigned char>(line[valStart]))) valStart++;
					std::string hVal = line.substr(valStart);
					while (!hVal.empty() && std::isspace(static_cast<unsigned char>(hVal.back()))) hVal.pop_back();
					if (hName == "origin") req.origin = hVal;
					else if (hName == "host") req.host = hVal;
					else if (hName == "cookie") req.cookie = hVal;
					else if (hName == "x-csrf") req.csrf = hVal;
					else if (hName == "user-agent") req.userAgent = hVal;
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
	// index_html.h stores the page as independent const char[] parts (each
	// its own flash-resident literal, never concatenated at compile time --
	// see that header's comment for why) rather than one combined constant.
	// This is the one place that ever pays for assembling them into a single
	// std::string, exactly like it did before that split existed.
	std::string page;
	{
		size_t total = 0;
		for (size_t i = 0; i < CGA_INDEX_HTML_PART_COUNT; ++i) total += CGA_INDEX_HTML_PARTS[i].size;
		page.reserve(total);
		for (size_t i = 0; i < CGA_INDEX_HTML_PART_COUNT; ++i) page.append(CGA_INDEX_HTML_PARTS[i].data, CGA_INDEX_HTML_PARTS[i].size);
	}

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

#if defined(ESP_PLATFORM)
// ── Issue #185: task-watchdog + heap/stack telemetry for GET /api/status ────
// Read-only and zero-coupling: every stack high-water mark below is looked up
// by FreeRTOS task NAME via xTaskGetHandle() rather than threading a
// TaskHandle_t out of SipServer/UdpServer/RtpSender/RtpReceiver/ConferenceRoom
// into this file, so none of those classes needs a getter added for this.
//
// The Task Watchdog SUBSCRIPTION (esp_task_wdt_add() + a periodic
// esp_task_wdt_reset()) is a separate mechanism and lives only in
// sip_server_task (main/esp_main*.cpp): the TWDT can only be fed by the
// subscribed task itself calling esp_task_wdt_reset() on its own behalf --
// there is no "reset on behalf of task X" call in the IDF API. This file runs
// on the HTTP task, not any of the five tasks #185 names, so it could not
// feed a subscription for udp_receiver_task / rtp_media_tx / rtp_media_rx /
// conf_mix_tick even if it added one here -- and an unfed subscription would
// guarantee a spurious watchdog reset under normal operation, not add safety.
// Those four tasks' loops live in UdpServer.cpp / RtpSender.cpp /
// RtpReceiver.cpp / ConferenceRoom.cpp, outside this change's file scope; see
// the PR description for exactly where their esp_task_wdt_add()/_reset() calls
// would go. sip_server_task (in scope, main/esp_main*.cpp) IS fully subscribed.

// xTaskGetHandle() asserts strlen(name) < configMAX_TASK_NAME_LEN (16 on this
// project's sdkconfig — FreeRTOS's own default). A task's STORED name is
// itself right-truncated to 15 chars + NUL at creation time (FreeRTOS
// tasks.c: prvInitialiseNewTask), so querying a longer literal doesn't just
// fail to match -- it trips that assert and aborts the board. "udp_receiver_
// task" is 17 chars; every other name below is short enough to pass whole.
#define PD_UDP_RECEIVER_TASK_NAME "udp_receiver_ta"   // truncated "udp_receiver_task"

// Stack high-water mark in BYTES for the task currently named `name`, or -1 if
// no such task exists right now. -1 (rendered as JSON null) is deliberately
// distinct from 0: rtp_media_tx/rx and conf_mix_tick only exist while a
// call/conference is active, so "not running" is the ordinary case and must
// stay distinguishable from an actual 0-bytes-left reading, which is the
// near-overflow alarm this field exists to surface (see MixBus::tick()'s ~2.9
// KB of locals on conf_mix_tick's 3072-byte stack, issue #185's motivating
// example).
static long pdStackHwmBytes(const char* name)
{
	TaskHandle_t h = xTaskGetHandle(name);
	if (h == nullptr)
	{
		return -1;
	}
	return static_cast<long>(uxTaskGetStackHighWaterMark(h)) * static_cast<long>(sizeof(StackType_t));
}

// sip_server_task is named "sip_server_task" on the wifi/softAP build
// (main/esp_main.cpp) but "sip_server" on both eth builds
// (main/esp_main_eth.cpp, main/esp_main_eth_lan8720.cpp). This one
// HttpServer.cpp links into all three, so try both spellings.
static long pdSipServerStackHwmBytes()
{
	TaskHandle_t h = xTaskGetHandle("sip_server_task");
	if (h == nullptr)
	{
		h = xTaskGetHandle("sip_server");
	}
	if (h == nullptr)
	{
		return -1;
	}
	return static_cast<long>(uxTaskGetStackHighWaterMark(h)) * static_cast<long>(sizeof(StackType_t));
}

static const char* pdResetReasonString(esp_reset_reason_t reason)
{
	switch (reason)
	{
		case ESP_RST_POWERON:    return "POWERON";
		case ESP_RST_EXT:        return "EXT_PIN";
		case ESP_RST_SW:         return "SW_RESTART";
		case ESP_RST_PANIC:      return "PANIC";
		case ESP_RST_INT_WDT:    return "INT_WDT";
		case ESP_RST_TASK_WDT:   return "TASK_WDT";
		case ESP_RST_WDT:        return "OTHER_WDT";
		case ESP_RST_DEEPSLEEP:  return "DEEPSLEEP_WAKE";
		case ESP_RST_BROWNOUT:   return "BROWNOUT";
		case ESP_RST_SDIO:       return "SDIO";
		case ESP_RST_USB:        return "USB";
		case ESP_RST_JTAG:       return "JTAG";
		case ESP_RST_EFUSE:      return "EFUSE_ERROR";
		case ESP_RST_PWR_GLITCH: return "PWR_GLITCH";
		case ESP_RST_CPU_LOCKUP: return "CPU_LOCKUP";
		default:                 return "UNKNOWN";
	}
}

// Appends ,"<key>":<bytes|null> -- the shared shape for every stackHwm_* field.
static void pdAppendHwmField(std::ostringstream& json, const char* key, long bytes)
{
	json << ",\"" << key << "\":";
	if (bytes < 0)
	{
		json << "null";
	}
	else
	{
		json << bytes;
	}
}
#endif // ESP_PLATFORM

void HttpServer::recordConnStackHwm()
{
#if defined(ESP_PLATFORM)
	// uxTaskGetStackHighWaterMark returns the smallest amount of free stack this
	// task has ever had, in WORDS on Xtensa -- multiply for the bytes every other
	// stackHwm_* field reports. Called on the connection thread itself, right
	// after the request has been served, so it covers whatever depth that
	// particular route reached.
	const long freeBytes =
		static_cast<long>(uxTaskGetStackHighWaterMark(nullptr)) * sizeof(StackType_t);

	// Keep the WORST (smallest-free) figure any connection has produced since
	// boot: a compare-exchange loop rather than a plain store, because several
	// connection threads can finish at once and the deepest one must win.
	long prev = _httpConnStackHwmBytes.load(std::memory_order_relaxed);
	while (prev < 0 || freeBytes < prev)
	{
		if (_httpConnStackHwmBytes.compare_exchange_weak(prev, freeBytes,
			std::memory_order_relaxed))
		{
			break;
		}
	}
#endif
}

void HttpServer::sendApiStatus(int sock, bool authenticated)
{
	uint64_t uptimeMs = currentTimeMs() - _startTime;
	uint64_t uptimeSec = uptimeMs / 1000;

	std::vector<std::pair<std::string, std::string>> clients;
	std::vector<std::tuple<std::string, std::string, std::string, int>> sessions;
	std::vector<std::string> dndExtensions;
	std::vector<std::string> voicemailExtensions;
	std::vector<std::tuple<std::string, std::string, std::string, std::string>> forwards;
	std::vector<std::tuple<std::string, std::string, std::string>> ringGroups;
	std::vector<std::tuple<std::string, std::string, std::string, int>> dialRules;
	std::vector<std::tuple<std::string, std::string, std::string, int>> parkedCalls;
	uint64_t packets = 0;
	uint64_t dropped = 0;

	RequestsHandler* handler = _handler.load(std::memory_order_acquire);
	if (handler != nullptr)
	{
		clients = handler->getActiveClients();
		sessions = handler->getActiveSessions();
		dndExtensions = handler->getDndExtensions();
		voicemailExtensions = handler->getVoicemailExtensions();
		forwards = handler->getForwards();
		ringGroups = handler->getRingGroups();
		dialRules = handler->getDialRules();
		parkedCalls = handler->getParkedCalls();
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
	// #167: state the board's WiFi capability rather than leaving the dashboard
	// to infer it from an empty scan result. An eth/lan8720 build has no radio at
	// all, so "found 0 networks" is not an empty scan -- it is a scan that can
	// never succeed, and the two are indistinguishable to a client without this.
#if defined(POCKETDIAL_HAS_WIFI)
	json << "\"wifiCapable\":true,";
#else
	json << "\"wifiCapable\":false,";
#endif
	json << "\"uptime\":" << uptimeSec << ",";
	json << "\"packetsProcessed\":" << packets << ",";
	json << "\"packetsDropped\":" << dropped << ",";

	// microSD, on builds that have a slot wired (currently the T-ETH-ELITE `eth`
	// board only). Always present so a client can tell "no card" from "this build
	// has no slot": `present` is the build capability, `mounted` the runtime fact.
#if defined(PD_ETH_HAS_SD)
	json << "\"sd\":{\"present\":true,\"mounted\":" << (pd_sd_mounted() ? "true" : "false")
	     << ",\"capacityMb\":" << pd_sd_capacity_mb() << "},";
#else
	json << "\"sd\":{\"present\":false,\"mounted\":false,\"capacityMb\":0},";
#endif

	// Clients array
	// #207: the roster is withheld from an unauthenticated caller. The counts
	// below stay visible -- "4 phones registered" is operational status, and the
	// dashboard shows it before login -- but WHICH extensions, at WHICH
	// addresses, is a target list and requires a session.
	json << "\"clients\":[";
	if (authenticated)
	{
		for (size_t i = 0; i < clients.size(); i++)
		{
			if (i > 0) json << ",";
			json << "{\"number\":\"" << jsonEscape(clients[i].first)
			     << "\",\"address\":\"" << jsonEscape(clients[i].second) << "\"}";
		}
	}
	json << "],";
	// The COUNT is not withheld -- "4 phones registered" is operational status the
	// dashboard shows before login, and it discloses no identity. Emitted
	// unconditionally so an unauthenticated client can tell "nobody is registered"
	// from "you are not allowed to see who is", which an empty array alone cannot.
	json << "\"clientCount\":" << clients.size() << ",";
	json << "\"rosterVisible\":" << (authenticated ? "true" : "false") << ",";

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

	// Voicemail array (Issue #246): extensions currently voicemail-enabled.
	json << "\"voicemail\":[";
	for (size_t i = 0; i < voicemailExtensions.size(); i++)
	{
		if (i > 0) json << ",";
		json << "\"" << jsonEscape(voicemailExtensions[i]) << "\"";
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

	// Dial-plan rules (Issue #69, stripDigits for the Trunk action Issue #165).
	// Emitted in TABLE ORDER — this array's order is load-bearing (first match
	// wins), unlike the sets above.
	json << "\"dialplan\":[";
	for (size_t i = 0; i < dialRules.size(); i++)
	{
		if (i > 0) json << ",";
		json << "{\"pattern\":\"" << jsonEscape(std::get<0>(dialRules[i]))
		     << "\",\"action\":\"" << jsonEscape(std::get<1>(dialRules[i]))
		     << "\",\"target\":\"" << jsonEscape(std::get<2>(dialRules[i]))
		     << "\",\"stripDigits\":" << std::get<3>(dialRules[i]) << "}";
	}
	json << "],";

	// Parked calls: {orbit, parkedExt, parker, secondsParked} — Issue #65's
	// ParkOrbit::snapshotRows(onlyParked=true), used by the dashboard to tell
	// a parked jack apart from an idle or actively-connected one.
	json << "\"parkedCalls\":[";
	for (size_t i = 0; i < parkedCalls.size(); i++)
	{
		if (i > 0) json << ",";
		json << "{\"orbit\":\"" << jsonEscape(std::get<0>(parkedCalls[i]))
		     << "\",\"parkedExt\":\"" << jsonEscape(std::get<1>(parkedCalls[i]))
		     << "\",\"parker\":\"" << jsonEscape(std::get<2>(parkedCalls[i]))
		     << "\",\"secondsParked\":" << std::get<3>(parkedCalls[i]) << "}";
	}
	json << "]";

	// Issue #185: task-watchdog / heap / per-task stack telemetry. Purely
	// additive -- every key here is new; nothing above this line changed.
#if defined(ESP_PLATFORM)
	json << ",\"freeHeap\":" << esp_get_free_heap_size();
	json << ",\"minFreeHeap\":" << esp_get_minimum_free_heap_size();
	json << ",\"minFreeHeapSpiram\":" << heap_caps_get_minimum_free_size(MALLOC_CAP_SPIRAM);
	// Issue #273: internal (DRAM) low-water, reported separately. The two
	// figures above cannot show a DRAM shortage -- MALLOC_CAP_SPIRAM is PSRAM
	// by definition, and the all-caps minimum is dominated by 8 MB of PSRAM,
	// so a near-exhausted 320 KB of DRAM barely moves it. Task stacks and
	// lwIP pbufs live here and nowhere else.
	json << ",\"minFreeHeapInternal\":" << heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL);
	// Issue #273, second pass: the field above is a LOW-WATER MARK since boot
	// (heap_caps_get_minimum_free_size), which is monotonically non-increasing
	// and therefore cannot distinguish a slow leak from one large transient
	// dip. It already caused a wrong conclusion on #273: a 7072 -> 3272 move
	// across a window containing both a quiet period and five /api/status
	// requests was read as background drain, when a single DMA bounce-buffer
	// allocation during one of those requests explains it just as well. A
	// watermark can only tell you the worst instant ever seen; it can never
	// recover, so "it went down" is not evidence about WHEN or WHY.
	//
	// These are instantaneous, and together they answer what the watermark
	// cannot. Total free and largest CONTIGUOUS block are reported separately
	// because the allocation that actually fails on this board is a
	// contiguous, ALIGNED one: spicommon_dma_setup_priv_buffer() ends in
	// heap_caps_aligned_alloc(alignment, align_len, mem_cap) (IDF
	// esp_driver_spi/src/gpspi/spi_common.c), so total free can look
	// comfortable while no single block is big enough. A widening gap between
	// freeHeapInternal and largestFreeBlock* is fragmentation; both falling
	// together is exhaustion. Nothing here decides which is happening -- that
	// is the point of reporting both.
	//
	// The DMA figure is reported alongside the INTERNAL one rather than
	// instead of it because that IDF call takes its caps from the CALLER
	// (mem_cap is a parameter), so MALLOC_CAP_INTERNAL is a proxy, not the
	// exact pool. On ESP32-S3 the two sets are nearly identical -- and
	// "nearly" is precisely the kind of word that has already produced wrong
	// conclusions on #273, so measure both and let the numbers say.
	json << ",\"freeHeapInternal\":" << heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
	json << ",\"largestFreeBlockInternal\":" << heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL);
	json << ",\"freeHeapDma\":" << heap_caps_get_free_size(MALLOC_CAP_DMA);
	json << ",\"largestFreeBlockDma\":" << heap_caps_get_largest_free_block(MALLOC_CAP_DMA);
	json << ",\"resetReason\":\"" << pdResetReasonString(esp_reset_reason()) << "\"";
	pdAppendHwmField(json, "stackHwm_sip_server_task", pdSipServerStackHwmBytes());
	pdAppendHwmField(json, "stackHwm_udp_receiver_task", pdStackHwmBytes(PD_UDP_RECEIVER_TASK_NAME));
	pdAppendHwmField(json, "stackHwm_rtp_media_tx", pdStackHwmBytes("rtp_media_tx"));
	pdAppendHwmField(json, "stackHwm_rtp_media_rx", pdStackHwmBytes("rtp_media_rx"));
	pdAppendHwmField(json, "stackHwm_conf_mix_tick", pdStackHwmBytes("conf_mix_tick"));
	// Issue #366: not a live-task lookup like the others -- a connection thread is
	// gone by the time anyone reads this -- but the worst figure recorded by any
	// of them since boot. null until the first request has completed, which in
	// practice means the very request being served here reports null on a fresh
	// boot and a real number from then on.
	pdAppendHwmField(json, "stackHwm_http_conn",
		_httpConnStackHwmBytes.load(std::memory_order_relaxed));
#else
	// Host build: no FreeRTOS, no heap_caps. Same key set as the ESP build,
	// all-zero/null, so tests/interop/interop.py's JSON parsing never has to
	// special-case platform -- matching this route's existing "counters read
	// 0, arrays empty" convention for the unattached/host case (docs/API.md).
	json << ",\"freeHeap\":0,\"minFreeHeap\":0,\"minFreeHeapSpiram\":0,\"minFreeHeapInternal\":0"
	        ",\"freeHeapInternal\":0,\"largestFreeBlockInternal\":0"
	        ",\"freeHeapDma\":0,\"largestFreeBlockDma\":0,\"resetReason\":\"n/a\"";
	json << ",\"stackHwm_sip_server_task\":null,\"stackHwm_udp_receiver_task\":null,"
	        "\"stackHwm_rtp_media_tx\":null,\"stackHwm_rtp_media_rx\":null,"
	        "\"stackHwm_conf_mix_tick\":null,\"stackHwm_http_conn\":null";
#endif

	json << "}";

	sendResponse(sock, 200, "OK", "application/json", json.str());
}

// GET /metrics (issue #184) — Prometheus text-exposition format, ported from
// drawbridge's issue #128 handler (its src/Helpers/HttpServer.cpp:1079
// sendApiMetrics). Every place this diverges from that original is recorded
// below, because the divergences are decisions, not drift.
//
// ── GATING: intentionally UNAUTHENTICATED ────────────────────────────────────
// This is the decision that matters, so it is argued rather than asserted.
//
//  1. docs/THREAT_MODEL.md §4 E-2 defines the read-only-and-unauthenticated
//     class (/api/status, /api/wifi/scan, /api/admin/status) and explicitly
//     separates it from the *sensitive* reads that do take requireAdmin()
//     (/api/pcap, /api/trace, /api/registrar, /api/telephony-config,
//     /api/did-mapping, /api/ap-security — raw SIP bytes including
//     Authorization digests, credentials-adjacent config, the AP passphrase in
//     clear). What this handler emits is six unlabelled aggregate numbers: no
//     extension numbers, no peer addresses, no caller/callee pairs, no config,
//     no secrets. It belongs in the first class, not the second.
//
//  2. /api/status is dispatched ungated from handleClient()'s route table (the
//     entry directly above /metrics, ~line 449) and returns strictly MORE than
//     this page does — the whole registered-client roster with each phone's
//     IP:port, every live session's caller/callee/state, the
//     dial plan, and the parked-call table. Gating /metrics while that stays
//     open would not withhold a single bit from an anonymous peer on the link;
//     it would only look like a control. Operational detail does leak here, but
//     it is a strict subset of what already leaks next door.
//
//  3. A stock Prometheus scraper cannot authenticate to this server even if we
//     wanted it to. It issues a bare GET with no cookie jar; it cannot drive
//     POST /api/admin/login, echo the per-session X-CSRF token, or renew the
//     30-minute sliding session. Putting requireAdmin() here would not harden
//     the endpoint — it would produce a permanently-401 route that no collector
//     could ever scrape, i.e. a feature that does not work. Drawbridge reached
//     the same conclusion for the same reason (its issue #128).
//
// So: ungated. A deployment that genuinely needs this hidden should control
// *reachability* (don't route the scrape network to the device), which is a
// lever that exists, rather than an auth gate the scrape protocol cannot
// satisfy. Note §5.5's standing rule still holds — reachability is not a
// security control for the admin plane; requireAdmin() is. This endpoint is
// simply not part of the admin plane.
//
// ── NAMING ───────────────────────────────────────────────────────────────────
// Every family is prefixed `pocketdial_`. That is a deliberate divergence:
// drawbridge shipped its families bare (`uptime_seconds`, `sip_calls_active`,
// `packets_processed_total`), which collides with any other exporter on the
// same Prometheus server and is against the convention that a family is
// namespaced by the application exporting it. The suffixes are drawbridge's
// verbatim, so the families stay recognisable across the two repos, and the
// prefix matches this codebase's own POCKETDIAL_ macro namespace.
//
// ── DATA SOURCES, and what was dropped ───────────────────────────────────────
// Reads only the thread-safe getters sendApiStatus already uses: the relaxed
// atomics (getPacketsProcessed / getPacketsDropped / getSdpRejected) and the
// _snapshotMutex-guarded counts (getClientCount / getSessionCount). Nothing
// here touches RequestsHandler::_mutex, the packet-path lock — which is why
// getConferenceLegs() (RequestsHandler.cpp:4951, the one dashboard getter that
// takes _mutex) is deliberately NOT exported: a scrape timer firing every
// 15 s would become the first HTTP-thread contender for the SIP hot path's
// lock, and a conference-legs gauge is not worth that.
//
// Drawbridge families with no source in pocket-dial are dropped, not faked:
// anchor_calls_active, anchor_connected, sip_registrations_total,
// sip_calls_total and rtp_playout_{underruns,overruns}_total all read a
// RequestsHandler::Telemetry struct that this repo does not have, and
// heap_free_bytes / psram_free_bytes have no counterpart in this server's
// status route.
void HttpServer::sendApiMetrics(int sock)
{
	uint64_t uptimeSec = (currentTimeMs() - _startTime) / 1000;

	uint64_t packets      = 0;
	uint64_t dropped      = 0;
	uint64_t sdpRejected  = 0;
	size_t   clientCount  = 0;
	size_t   sessionCount = 0;

	// Same null-check idiom as sendApiStatus: the dashboard starts before the
	// SIP stack exists (see attachHandler's comment in the header), so an
	// unattached server must still answer 200 with all-zero samples rather than
	// 503. Zero is a valid sample; a missing family would make a collector
	// report the series as stale.
	RequestsHandler* handler = _handler.load(std::memory_order_acquire);
	if (handler != nullptr)
	{
		packets      = handler->getPacketsProcessed();
		dropped      = handler->getPacketsDropped();
		sdpRejected  = handler->getSdpRejected();
		clientCount  = handler->getClientCount();
		sessionCount = handler->getSessionCount();
	}

	// Exposition format 0.0.4 is a strict line protocol: "# HELP <name> <text>"
	// then "# TYPE <name> <counter|gauge>" then one bare-number sample line per
	// family, LF-separated (never CRLF — that is the response *header*
	// convention, not the body's), and the body ends with a final LF.
	//
	// A monotonic series MUST be declared `counter`, never `gauge`: rate() and
	// increase() only apply their counter-reset correction to a family typed
	// counter, so mistyping one would make every reboot read as a large
	// negative rate instead of a reset.
	std::ostringstream out;
	auto gauge = [&out](const char* name, const char* help, uint64_t value) {
		out << "# HELP " << name << " " << help << "\n";
		out << "# TYPE " << name << " gauge\n";
		out << name << " " << value << "\n";
	};
	auto counter = [&out](const char* name, const char* help, uint64_t value) {
		out << "# HELP " << name << " " << help << "\n";
		out << "# TYPE " << name << " counter\n";
		out << name << " " << value << "\n";
	};

	// Uptime is monotonic-since-boot but is a gauge by convention (and by
	// drawbridge's choice): it is read as "how long has this board been up",
	// a point-in-time value, and is never rate()'d. Only the _total families
	// below are counters.
	gauge("pocketdial_uptime_seconds",
	      "Seconds since this boot.", uptimeSec);
	// Both of these read the dashboard snapshot, which tick() republishes on its
	// own ~1 s cadence (RequestsHandler.cpp's snapshot build) — so they lag live
	// state by up to a tick. That is well inside any sane scrape interval, but it
	// is why neither is described as "exact".
	gauge("pocketdial_sip_registrations_active",
	      "Extensions holding a registration binding, as of the last snapshot.",
	      static_cast<uint64_t>(clientCount));
	gauge("pocketdial_sip_calls_active",
	      "Sessions allocated in the session map, as of the last snapshot. Counts "
	      "internal legs (register beep, echo, park ring-back), not just "
	      "handset-to-handset calls.",
	      static_cast<uint64_t>(sessionCount));
	counter("pocketdial_packets_processed_total",
	        "SIP packets accepted and dispatched since boot.", packets);
	counter("pocketdial_packets_dropped_total",
	        "SIP packets dropped since boot as malformed or rate-limited (issue #38).",
	        dropped);
	counter("pocketdial_sdp_rejected_total",
	        "SDP bodies refused by the admission gate since boot, whether answered 488 "
	        "or dropped silently (docs/THREAT_MODEL.md T-7).",
	        sdpRejected);

	// "text/plain; version=0.0.4" is THE exposition-format content type — the
	// version parameter is how a scraper picks its parser, so it is not
	// decorative. sendResponse passes the string through verbatim.
	sendResponse(sock, 200, "OK", "text/plain; version=0.0.4; charset=utf-8", out.str());
}

void HttpServer::sendApiKill(int sock, const std::string& body)
{
	// Issue #191: this used to hand-roll the parse — a bare body.find("extension=")
	// followed by a substr() to the end of the body — and so reproduced, one for
	// one, every defect getFormParam() exists to prevent:
	//
	//   1. find() matched a key that merely ENDS in "extension", so a body of
	//      "myextension=999&extension=101" disconnected 999 and left the jack the
	//      operator actually clicked still up. This is exactly the bug class the
	//      helper's own boundary check carries the scar of (see getFormParam's
	//      comment below): searching for "on=" inside "extension=101&on=1" hit the
	//      "n=" of "extensio[n=]101", and DND silently inverted.
	//   2. the substr() ran to the END of the body rather than to the next '&',
	//      so "extension=101&reason=test" yielded ext = "101&reason=test" — a
	//      string no registered client can ever equal, i.e. a kill that matched
	//      nothing while still answering 200.
	//   3. no URL-decoding at all, so a percent-encoded extension was compared
	//      literally. isValidAor admits '*' and '#' (park orbits, page zones, the
	//      *8 group-pickup code — see PbxConfig.hpp), and those reach a form body
	//      as escapes from any conservative encoder: curl --data-urlencode and
	//      Python's quote() both send "*8" as "%2A8". Even the dashboard's
	//      encodeURIComponent(), which leaves '*' alone, sends a '#'-bearing code
	//      as "%23". None of those ever equalled a registered client's number.
	//
	// One deliberate behaviour change falls out of (1): a body carrying ONLY
	// "myextension=999" now answers 400 instead of killing 999. That is the fix,
	// not a regression — and the real caller (index_html.h's
	// post("/api/kill","extension="+encodeURIComponent(selectedJack))) puts
	// "extension=" at offset 0, which the boundary check admits unchanged.
	const std::string ext = getFormParam(body, "extension");

	if (ext.empty())
	{
		sendResponse(sock, 400, "Bad Request", "application/json",
		             "{\"error\":\"missing extension parameter\"}");
		return;
	}

	// KNOWN GAP (issue #191, second half): this answers 200 whether or not the
	// extension matched anything, so an operator clearing a stuck phone is told
	// it worked even when no client and no session bore that number — precisely
	// the outcome defect (2) above produced on every call. Reporting 404
	// needs RequestsHandler::forceDisconnect() to return whether it matched
	// (the signal already exists inside it: the _clientPool number compare and
	// the per-session `involved` flag), which is a change to another translation
	// unit, so it is left for a follow-up rather than faked from this side.
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
	// This handler ASSUMES it was reached through requireAdmin() and re-checks
	// nothing: the two routes that reach it (/api/pcap and /api/diagnostics/pcap —
	// sendApiTrace next door serves the same ring behind the same gate) both go
	// through requireAdmin(..., needCsrf=false), whose FIRST gate is
	// requireSameOrigin() — so same-origin and a valid session are already
	// established by the time these bytes are built. The guard lives at the
	// dispatch site, not here.
	//
	// What needCsrf=false means, which is all this comment was ever trying to say:
	// a plain-download GET (an admin clicking a dashboard link, or curl/wget with
	// the session cookie) mutates nothing, and the CSRF token defends against a
	// hostile page driving a state change THROUGH an admin's browser — it can
	// forge the request but never read the response. SameSite=Strict on pd_session
	// (see /api/admin/login) is the defence in depth that stops such a page
	// reaching this at all.
	//
	// The comment this replaces claimed "No same-origin check" — true of this
	// function read in isolation, false of the endpoint as dispatched. It predates
	// the sweep that put these read routes behind requireAdmin (see
	// HttpServer.hpp's requireAdmin comment: "/api/pcap, /api/trace and
	// /api/diagnostics/pcap had no same-origin check despite serving raw SIP bytes
	// including Authorization digests"). docs/API.md now lists /api/pcap among the
	// same-origin-checked "gated reads", so this comment was the last place the old
	// claim still stood — and a security note that disagrees with the dispatch
	// table is exactly how a wrong claim gets repeated downstream. Hence: say where
	// the guard lives, not whether this function performs it.
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

HttpServer::ProvisioningPathType HttpServer::parseProvisioningPath(
	const std::string& path, std::string& outKey)
{
	outKey.clear();
	static const std::string prefix = "/config/";
	if (path.size() <= prefix.size() || path.compare(0, prefix.size(), prefix) != 0)
	{
		return ProvisioningPathType::Invalid;
	}

	const std::string filename = path.substr(prefix.size());

	auto is12LowerHex = [](const std::string& s) {
		if (s.size() != 12) return false;
		for (char c : s)
		{
			bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
			if (!hex) return false;
		}
		return true;
	};

	// 1. Polycom master/generic config: 000000000000.cfg (Issue #234 Gap 3)
	if (filename == "000000000000.cfg") return ProvisioningPathType::PolycomMaster;

	// 2. Grandstream: cfg<12 hex>.xml (19 chars: "cfg" + 12 hex + ".xml")
	if (filename.size() == 19 && filename.compare(0, 3, "cfg") == 0 &&
	    filename.compare(15, 4, ".xml") == 0)
	{
		std::string mac = filename.substr(3, 12);
		if (is12LowerHex(mac)) { outKey = mac; return ProvisioningPathType::Grandstream; }
	}

	// 3. Polycom per-phone: <12 hex>-phone.cfg (22 chars: 12 hex + "-phone.cfg")
	if (filename.size() == 22 && filename.compare(12, 10, "-phone.cfg") == 0)
	{
		std::string mac = filename.substr(0, 12);
		if (is12LowerHex(mac)) { outKey = mac; return ProvisioningPathType::PolycomPhone; }
	}

	// 4. Cisco SPA macro-expanded: spa<12 hex>.cfg (19 chars: "spa" + 12 hex + ".cfg")
	if (filename.size() == 19 && filename.compare(0, 3, "spa") == 0 &&
	    filename.compare(15, 4, ".cfg") == 0)
	{
		std::string mac = filename.substr(3, 12);
		if (is12LowerHex(mac)) { outKey = mac; return ProvisioningPathType::CiscoSpaMac; }
	}

	// 5. Cisco SPA model-keyed: spa<model>.cfg (e.g. spa504g.cfg)
	if (filename.size() > 7 && filename.compare(0, 3, "spa") == 0 &&
	    filename.compare(filename.size() - 4, 4, ".cfg") == 0)
	{
		std::string model = filename.substr(3, filename.size() - 7);
		if (model.size() >= 2 && model.size() <= 8)
		{
			bool validModel = true;
			for (char c : model) if (!std::isalnum(static_cast<unsigned char>(c))) { validModel = false; break; }
			if (validModel) { outKey = model; return ProvisioningPathType::CiscoSpaModel; }
		}
	}

	// 6. Yealink / default: <12 hex>.cfg (16 chars: 12 hex + ".cfg")
	if (filename.size() == 16 && filename.compare(12, 4, ".cfg") == 0)
	{
		std::string mac = filename.substr(0, 12);
		if (is12LowerHex(mac)) { outKey = mac; return ProvisioningPathType::Yealink; }
	}

	return ProvisioningPathType::Invalid;
}

bool HttpServer::isProvisioningConfigPath(const std::string& path)
{
	std::string unused;
	return parseProvisioningPath(path, unused) != ProvisioningPathType::Invalid;
}

void HttpServer::sendProvisioningResponse(int sock, const HttpRequest& req)
{
	std::string key;
	ProvisioningPathType type = parseProvisioningPath(req.path, key);
	if (type == ProvisioningPathType::Invalid)
	{
		send404(sock);
		return;
	}

	// 1. Polycom master/generic config: served directly without registry lookup (Issue #234 Gap 3)
	if (type == ProvisioningPathType::PolycomMaster)
	{
		std::string cfg = provisioning::polycomBaseConfigFor();
		sendResponse(sock, 200, "OK", "application/xml", cfg);
		return;
	}

	std::string activeIp = (_ip == "0.0.0.0") ? getPrimaryLocalIP() : _ip;
	RequestsHandler* handler = _handler.load(std::memory_order_acquire);

	// 2. Cisco SPA model-keyed request (e.g. spa504g.cfg): resolve via ARP or serve Profile_Rule redirect
	if (type == ProvisioningPathType::CiscoSpaModel)
	{
		std::string mac;
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
		if (!req.clientIp.empty())
		{
			struct sockaddr_in sa;
			std::memset(&sa, 0, sizeof(sa));
			sa.sin_family = AF_INET;
			if (inet_pton(AF_INET, req.clientIp.c_str(), &sa.sin_addr) == 1)
			{
				auto macOpt = ArpLookup::pdLookupMac(sa);
				if (macOpt.has_value())
				{
					mac = ArpLookup::toHex12(*macOpt);
				}
			}
		}
#endif
		if (!mac.empty())
		{
			auto info = handler ? handler->findProvisioningInfo(mac) : std::nullopt;
			if (info)
			{
				std::string cfg = provisioning::ciscoSpaConfigFor(
					info->extension, activeIp, 5060, info->authRequired);
				if (!cfg.empty())
				{
					sendResponse(sock, 200, "OK", "application/xml", cfg);
					return;
				}
			}
		}

		std::string bootstrap =
			"<flat-profile>\r\n"
			"<!-- Auto-generated by pocket-dial. Issues #35, #234: Cisco SPA bootstrap -->\r\n"
			"<Profile_Rule>http://" + activeIp + "/config/spa$MA.cfg</Profile_Rule>\r\n"
			"</flat-profile>\r\n";
		sendResponse(sock, 200, "OK", "application/xml", bootstrap);
		return;
	}

	// 3. MAC-keyed provisioning paths (Yealink, Grandstream, PolycomPhone, CiscoSpaMac)
	auto info = handler ? handler->findProvisioningInfo(key) : std::nullopt;
	if (!info)
	{
		send404(sock);
		return;
	}

	std::string cfg;
	std::string contentType = "application/xml";

	if (type == ProvisioningPathType::Grandstream)
	{
		cfg = provisioning::grandstreamConfigFor(info->extension, activeIp, 5060, info->authRequired);
	}
	else if (type == ProvisioningPathType::PolycomPhone)
	{
		cfg = provisioning::polycomPhoneConfigFor(info->extension, activeIp, 5060, info->authRequired);
	}
	else if (type == ProvisioningPathType::CiscoSpaMac)
	{
		cfg = provisioning::ciscoSpaConfigFor(info->extension, activeIp, 5060, info->authRequired);
	}
	else // ProvisioningPathType::Yealink (/config/<mac>.cfg)
	{
		provisioning::Vendor vendor = provisioning::detectVendorFromUserAgent(req.userAgent);
		cfg = provisioning::renderProvisioningConfigForUserAgent(
			req.userAgent, info->extension, activeIp, 5060, info->authRequired);
		if (vendor == provisioning::Vendor::Yealink)
		{
			contentType = "text/plain";
		}
	}

	if (cfg.empty())
	{
		send404(sock);
		return;
	}
	sendResponse(sock, 200, "OK", contentType, cfg);
}

void HttpServer::sendConfigCfg(int sock, const std::string& mac)
{
	HttpRequest req;
	req.method = "GET";
	req.path = "/config/" + mac + ".cfg";
	sendProvisioningResponse(sock, req);
}

void HttpServer::sendApiVoicemail(int sock, const std::string& body)
{
	std::string ext = getFormParam(body, "extension");
	std::string on  = getFormParam(body, "on");

	if (ext.empty())
	{
		sendResponse(sock, 400, "Bad Request", "application/json",
		             "{\"error\":\"missing extension parameter\"}");
		return;
	}

	// Use the full reserved/emergency literal set (pbx::isReservedExtension:
	// 777/999/888/555/440/911/933/796 -- 796 is the voicemail retrieval
	// pilot itself, Issue #246) rather than sendApiDnd's narrower
	// hand-picked list (777/999/555) -- new code, no reason to carry over an
	// existing gap. Also block the whole park-orbit range (700-709): an
	// orbit isn't a mailbox owner. (Was a stale `ext == "700"` literal from
	// when 700 was the originally-planned pilot number -- see
	// pbx::isReservedExtension()'s own comment for why that number moved.)
	if (pbx::isReservedExtension(ext) || pbx::isParkOrbitExt(ext))
	{
		sendResponse(sock, 400, "Bad Request", "application/json",
		             "{\"error\":\"cannot set voicemail on a virtual extension\"}");
		return;
	}
	if (pbx::isServiceName(ext))
	{
		sendResponse(sock, 400, "Bad Request", "application/json",
		             "{\"error\":\"cannot set voicemail on a service extension\"}");
		return;
	}

	bool enable = (on == "1" || on == "true" || on == "on");

	if (RequestsHandler* handler = _handler.load(std::memory_order_acquire))
	{
		handler->setVoicemail(ext, enable);
	}

	sendResponse(sock, 200, "OK", "application/json",
	             "{\"status\":\"ok\",\"extension\":\"" + jsonEscape(ext) +
	             "\",\"voicemail\":" + (enable ? "true" : "false") + "}");
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
	// Issue #202: same answer for an engine-owned service name (pbx/moh/server).
	if (pbx::isServiceName(ext))
	{
		sendResponse(sock, 400, "Bad Request", "application/json",
		             "{\"error\":\"cannot set DND on a service extension\"}");
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
	// Issue #202. Two different refusals, and they are not the same question:
	// a service may not be the SUBSCRIBER (it has no calls of its own to divert),
	// and a service that cannot receive calls may not be the TARGET (the forward
	// would be accepted and then black-hole every call it caught, which is the
	// failure the issue was filed about). setForwardLocked applies the identical
	// pair so the *72/*73 DTMF path is guarded too — this is the HTTP-facing half.
	if (pbx::isServiceName(ext))
	{
		sendResponse(sock, 400, "Bad Request", "application/json",
		             "{\"error\":\"cannot forward a service extension\"}");
		return;
	}
	if (!target.empty() && pbx::isServiceName(target) && !pbx::isDialableService(target))
	{
		sendResponse(sock, 400, "Bad Request", "application/json",
		             "{\"error\":\"service extension cannot receive calls\"}");
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
	// Issue #202: a group under a service name would shadow it — ring groups are
	// resolved before the extension lookup in onInvite.
	if (pbx::isServiceName(ext))
	{
		sendResponse(sock, 400, "Bad Request", "application/json",
		             "{\"error\":\"cannot use a service extension as a group\"}");
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
	// Issue #69 (Trunk action Issue #165). Params: pattern (the rule's key),
	// action ("group"|"page"|"park"|"trunk"), target (the group/zone/orbit
	// extension, or — for "trunk" — the digit string prepended after
	// stripping), stripDigits (trunk only: leading digits removed from the
	// dialed string before prepending target). An empty target deletes the
	// rule. The dial plan is ORDERED and first-match-wins, so an existing
	// pattern is edited in place (keeping its position) and a new one is
	// appended — see RequestsHandler::setDialRule, which owns the full
	// validation and the POCKETDIAL_MAX_DIAL_RULES cap.
	std::string pattern = getFormParam(body, "pattern");
	std::string action  = getFormParam(body, "action");
	std::string target  = getFormParam(body, "target");
	std::string stripDigitsStr = getFormParam(body, "stripDigits");

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
	if (pbx::isReservedExtension(pattern))
	{
		sendResponse(sock, 400, "Bad Request", "application/json",
		             "{\"error\":\"cannot use a reserved extension as a dial-plan pattern\"}");
		return;
	}
	// Issue #202: and no rule may claim a service name either. isDialTokenSafe
	// above admits letters, so "pbx" is a perfectly legal pattern as far as the
	// validator is concerned — this is the check that makes it not a legal one.
	if (pbx::isServiceName(pattern))
	{
		sendResponse(sock, 400, "Bad Request", "application/json",
		             "{\"error\":\"cannot use a service extension as a dial-plan pattern\"}");
		return;
	}

	int stripDigits = 0;
	// A delete only needs the pattern (and names no action); everything else is
	// validated for an upsert. Naming an action ALWAYS means upsert, because a
	// trunk rule may legitimately carry an empty target — that is how you say
	// "strip N digits and prepend nothing", which is otherwise inexpressible.
	if (!action.empty() || !target.empty())
	{
		if (action.empty()) action = "group";
		pbx::DialActionType parsed;
		if (!pbx::parseDialAction(action, parsed))
		{
			sendResponse(sock, 400, "Bad Request", "application/json",
			             "{\"error\":\"action must be group|page|park|trunk\"}");
			return;
		}
		if (!target.empty() && !pbx::isDialTokenSafe(target))
		{
			sendResponse(sock, 400, "Bad Request", "application/json",
			             "{\"error\":\"target may contain only letters, digits, '#' and '*'\"}");
			return;
		}
		if (target.empty() && parsed != pbx::DialActionType::Trunk)
		{
			sendResponse(sock, 400, "Bad Request", "application/json",
			             "{\"error\":\"only a trunk rule may have an empty target (it means prepend nothing)\"}");
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
		if (parsed == pbx::DialActionType::Trunk)
		{
			// Digits only, and short — this is a strip COUNT, not a phone number;
			// reject anything else outright rather than feeding atoi() garbage
			// (a leading '-' would parse to a negative stripDigits, atoi's other
			// failure mode returns 0, silently accepting a typo as "strip nothing").
			bool digitsOnly = !stripDigitsStr.empty() && stripDigitsStr.size() <= 3 &&
				std::all_of(stripDigitsStr.begin(), stripDigitsStr.end(),
					[](unsigned char c) { return std::isdigit(c); });
			if (!stripDigitsStr.empty() && !digitsOnly)
			{
				sendResponse(sock, 400, "Bad Request", "application/json",
				             "{\"error\":\"stripDigits must be a small non-negative integer\"}");
				return;
			}
			stripDigits = stripDigitsStr.empty() ? 0 : std::atoi(stripDigitsStr.c_str());
			if (pattern.back() != '*' && static_cast<size_t>(stripDigits) > pattern.size())
			{
				sendResponse(sock, 400, "Bad Request", "application/json",
				             "{\"error\":\"stripDigits exceeds this pattern's fixed length\"}");
				return;
			}
		}
	}

	if (RequestsHandler* handler = _handler.load(std::memory_order_acquire))
	{
		handler->setDialRule(pattern, action, target, stripDigits);
	}

	sendResponse(sock, 200, "OK", "application/json",
	             "{\"status\":\"ok\",\"pattern\":\"" + jsonEscape(pattern) +
	             "\",\"action\":\"" + jsonEscape(action) +
	             "\",\"target\":\"" + jsonEscape(target) +
	             "\",\"stripDigits\":" + std::to_string(stripDigits) + "}");
}

// ── Telephony-API credential slots (ported from drawbridge) ──────────────────

// "/api/telephony-config/<digits>" with no further path segment -- used for
// PUT (set one slot). `slotIdx` accepts any digit string that fits a size_t;
// range-checking against TelephonyApiConfig::kSlots is deliberately left to
// RequestsHandler::setTelephonyConfigSlot() (-> TelephonyApiConfig::setSlot()),
// so there is exactly one place in the codebase that knows the valid range.
static bool parseTelephonyConfigSlotPath(const std::string& path, size_t& slotIdx)
{
	static const std::string prefix = "/api/telephony-config/";
	if (path.size() <= prefix.size() || path.compare(0, prefix.size(), prefix) != 0)
	{
		return false;
	}
	const std::string rest = path.substr(prefix.size());
	// No legitimate slot index needs more than a handful of digits; capping the
	// length keeps the accumulation below overflow-free of any extra guard.
	if (rest.empty() || rest.size() > 9 || rest.find('/') != std::string::npos)
	{
		return false;
	}
	size_t v = 0;
	for (char c : rest)
	{
		if (!std::isdigit(static_cast<unsigned char>(c))) return false;
		v = v * 10 + static_cast<size_t>(c - '0');
	}
	slotIdx = v;
	return true;
}

// Same prefix, but requires a trailing "/activate" segment -- used for
// POST .../<slot>/activate.
static bool parseTelephonyConfigActivatePath(const std::string& path, size_t& slotIdx)
{
	static const std::string suffix = "/activate";
	if (path.size() <= suffix.size() ||
	    path.compare(path.size() - suffix.size(), suffix.size(), suffix) != 0)
	{
		return false;
	}
	return parseTelephonyConfigSlotPath(path.substr(0, path.size() - suffix.size()), slotIdx);
}

// Same prefix, but requires a trailing "/test" segment -- used for
// POST .../<slot>/test (Issue #165's dashboard patch-bay: the interconnect
// module's "Test Dial" action).
static bool parseTelephonyConfigTestPath(const std::string& path, size_t& slotIdx)
{
	static const std::string suffix = "/test";
	if (path.size() <= suffix.size() ||
	    path.compare(path.size() - suffix.size(), suffix.size(), suffix) != 0)
	{
		return false;
	}
	return parseTelephonyConfigSlotPath(path.substr(0, path.size() - suffix.size()), slotIdx);
}

// Shared JSON shape for one slot, used by both the GET list and the PUT/activate
// single-slot echo below. Mirrors TelephonyApiConfig::SlotView's own
// secretSet-not-secret contract: the plaintext secret never appears here.
static std::string telephonySlotJson(size_t idx, const TelephonyApiConfig::SlotView& v)
{
	std::ostringstream json;
	json << "{\"index\":" << idx
	     << ",\"type\":\"" << telephonyProviderName(v.type) << "\""
	     << ",\"enabled\":" << (v.enabled ? "true" : "false")
	     << ",\"implemented\":" << (v.implemented ? "true" : "false")
	     << ",\"active\":" << (v.active ? "true" : "false")
	     << ",\"baseUrl\":\"" << jsonEscape(v.baseUrl) << "\""
	     << ",\"clientId\":\"" << jsonEscape(v.clientId) << "\""
	     << ",\"routeDn\":\"" << jsonEscape(v.routeDn) << "\""
	     << ",\"secretSet\":" << (v.secretSet ? "true" : "false")
	     << "}";
	return json.str();
}

void HttpServer::sendApiTelephonyConfigList(int sock)
{
	std::vector<TelephonyApiConfig::SlotView> slots;
	if (RequestsHandler* handler = _handler.load(std::memory_order_acquire))
	{
		slots = handler->getTelephonyConfigSlots();
	}

	std::ostringstream json;
	json << "{\"slots\":[";
	for (size_t i = 0; i < slots.size(); ++i)
	{
		if (i > 0) json << ",";
		json << telephonySlotJson(i, slots[i]);
	}
	json << "]}";
	sendResponse(sock, 200, "OK", "application/json", json.str());
}

void HttpServer::sendApiTelephonyConfigSet(int sock, size_t slotIdx, const std::string& body)
{
	// Params: enabled ("1"/"true"/"on", same convention as sendApiDnd's "on"),
	// baseUrl, clientId, secret, routeDn. An empty secret means "keep existing"
	// (TelephonyApiConfig::setSlot's keepSecret param). `type` is deliberately
	// NOT a parameter here: this endpoint only ever configures
	// TelephonyProviderType::Telephony credentials -- the one real,
	// vendor-neutral provider this class exists for (see TelephonyProvider.hpp).
	// Loopback is the internal default and is never set through this API. Like
	// sendApiForward/sendApiGroup above, this is a full-replace PUT (except for
	// the secret carve-out): omitting `enabled` leaves the slot disabled.
	std::string enabledParam = getFormParam(body, "enabled");
	std::string baseUrl      = getFormParam(body, "baseUrl");
	std::string clientId     = getFormParam(body, "clientId");
	std::string secret       = getFormParam(body, "secret");
	std::string routeDn      = getFormParam(body, "routeDn");

	TelephonyApiConfig::Slot s;
	s.type     = TelephonyProviderType::Telephony;
	s.enabled  = (enabledParam == "1" || enabledParam == "true" || enabledParam == "on");
	s.baseUrl  = baseUrl;
	s.clientId = clientId;
	s.secret   = secret;
	s.routeDn  = routeDn;
	const bool keepSecret = secret.empty();

	TelephonyApiConfig::SlotView view;
	if (RequestsHandler* handler = _handler.load(std::memory_order_acquire))
	{
		std::string err = handler->setTelephonyConfigSlot(slotIdx, s, keepSecret);
		if (!err.empty())
		{
			sendResponse(sock, 400, "Bad Request", "application/json",
			             "{\"error\":\"" + jsonEscape(err) + "\"}");
			return;
		}
		view = handler->getTelephonyConfigSlot(slotIdx);
	}
	else
	{
		// No SIP engine attached yet (HttpServer can start before RequestsHandler
		// exists -- see this class's constructor comment); nothing was
		// persisted. Echo the request back, same convention as
		// sendApiForward/sendApiGroup above.
		view.type        = s.type;
		view.enabled     = s.enabled;
		view.implemented = telephonyProviderImplemented(s.type);
		view.baseUrl     = s.baseUrl;
		view.clientId    = s.clientId;
		view.routeDn     = s.routeDn;
		view.secretSet   = !s.secret.empty();
	}

	sendResponse(sock, 200, "OK", "application/json",
	             "{\"status\":\"ok\",\"slot\":" + telephonySlotJson(slotIdx, view) + "}");
}

void HttpServer::sendApiTelephonyConfigActivate(int sock, size_t slotIdx)
{
	if (RequestsHandler* handler = _handler.load(std::memory_order_acquire))
	{
		std::string err = handler->setTelephonyConfigActiveSlot(slotIdx);
		if (!err.empty())
		{
			sendResponse(sock, 400, "Bad Request", "application/json",
			             "{\"error\":\"" + jsonEscape(err) + "\"}");
			return;
		}
	}
	sendResponse(sock, 200, "OK", "application/json",
	             "{\"status\":\"ok\",\"activeIndex\":" + std::to_string(slotIdx) + "}");
}

void HttpServer::sendApiTelephonyConfigTest(int sock, size_t slotIdx)
{
	if (RequestsHandler* handler = _handler.load(std::memory_order_acquire))
	{
		RequestsHandler::TestDialResult result = handler->testDialSlot(slotIdx);
		if (!result.ok)
		{
			sendResponse(sock, 200, "OK", "application/json",
			             "{\"ok\":false,\"error\":\"" + jsonEscape(result.error) + "\"}");
			return;
		}
		sendResponse(sock, 200, "OK", "application/json",
		             "{\"ok\":true,\"participantId\":\"" + jsonEscape(result.participantId) + "\"}");
		return;
	}
	sendResponse(sock, 200, "OK", "application/json",
	             "{\"ok\":false,\"error\":\"no handler attached\"}");
}

void HttpServer::sendApiTelephonyConfigDelete(int sock, size_t slotIdx)
{
	// Lets an operator remove a stored secret short of a full factory reset.
	// TelephonyApiConfig::clearSlot() owns the bound check (same "there is
	// exactly one place that knows the valid range" contract as PUT above),
	// so an out-of-range index surfaces as a 400 from setSlot's sibling
	// rather than a duplicate check here.
	TelephonyApiConfig::SlotView view;
	if (RequestsHandler* handler = _handler.load(std::memory_order_acquire))
	{
		std::string err = handler->clearTelephonyConfigSlot(slotIdx);
		if (!err.empty())
		{
			sendResponse(sock, 400, "Bad Request", "application/json",
			             "{\"error\":\"" + jsonEscape(err) + "\"}");
			return;
		}
		view = handler->getTelephonyConfigSlot(slotIdx);
	}
	sendResponse(sock, 200, "OK", "application/json",
	             "{\"status\":\"ok\",\"slot\":" + telephonySlotJson(slotIdx, view) + "}");
}

// ── DID -> extension inbound routing (new) ────────────────────────────────────

static std::string didMappingJson(const DidMapping::Entry& e)
{
	return "{\"did\":\"" + jsonEscape(e.did) + "\",\"extension\":\"" +
	       jsonEscape(e.extension) + "\"}";
}

void HttpServer::sendApiE911Get(int sock)
{
	std::string exts, callback, location;
	if (RequestsHandler* handler = _handler.load(std::memory_order_acquire))
	{
		std::tie(exts, callback, location) = handler->getE911Config();
	}

	std::ostringstream json;
	json << "{\"notifyExts\":\"" << jsonEscape(exts) << "\","
	     << "\"callback\":\"" << jsonEscape(callback) << "\","
	     << "\"location\":\"" << jsonEscape(location) << "\","
	     << "\"maxNotifyExts\":" << pbx::kMaxE911NotifyExts << "}";
	sendResponse(sock, 200, "OK", "application/json", json.str());
}

void HttpServer::sendApiE911Set(int sock, const std::string& body)
{
	// Issue #166 (Kari's Law). Params: notifyExts (space/comma delimited),
	// callback, location. All three are optional -- an empty notifyExts is the
	// legitimate way to turn SIP notification off, and the syslog record at
	// Alert severity is emitted regardless of what is configured here.
	//
	// Only the charset gate lives here. PbxFeatureConfig::setE911Config() is
	// deliberately TOTAL -- it drops an unusable field and keeps the rest rather
	// than refusing the whole write -- because a rejected config would leave the
	// previous notify list silently in place while the operator believed they
	// had changed who gets told when somebody dials 911.
	const std::string exts     = getFormParam(body, "notifyExts");
	const std::string callback = getFormParam(body, "callback");
	const std::string location = getFormParam(body, "location");

	for (const std::string& e : pbx::splitMembers(exts))
	{
		if (!pbx::isDialTokenSafe(e))
		{
			sendResponse(sock, 400, "Bad Request", "application/json",
			             "{\"error\":\"notifyExts may contain only extensions, separated by spaces or commas\"}");
			return;
		}
	}
	if (!callback.empty() && !pbx::isDialTokenSafe(callback))
	{
		sendResponse(sock, 400, "Bad Request", "application/json",
		             "{\"error\":\"callback may contain only digits, letters, '#' and '*'\"}");
		return;
	}

	if (RequestsHandler* handler = _handler.load(std::memory_order_acquire))
	{
		handler->setE911Config(exts, callback, location);
	}
	// Echo the stored result, so a caller sees what was actually kept after
	// truncation to kMaxE911NotifyExts and any dropped field.
	sendApiE911Get(sock);
}

void HttpServer::sendApiSbcModeGet(int sock)
{
	bool enabled = false;
	size_t route = 0;
	if (RequestsHandler* handler = _handler.load(std::memory_order_acquire))
	{
		std::tie(enabled, route) = handler->getSbcMode();
	}

	std::ostringstream json;
	json << "{\"enabled\":" << (enabled ? "true" : "false")
	     << ",\"route\":" << route
	     << ",\"maxRoute\":" << TelephonyApiConfig::kSlots << "}";
	sendResponse(sock, 200, "OK", "application/json", json.str());
}

void HttpServer::sendApiSbcModeSet(int sock, const std::string& body)
{
	// Issue #201. Params: enabled ("1"/"true"/"on"), route (a
	// TelephonyApiConfig slot index as a decimal string). Enabling with a bad
	// route is a 400 -- see RequestsHandler::setSbcMode()'s doc comment for
	// why that leaves the previous SBC state untouched rather than turning it
	// on against a slot this build refused.
	const std::string enabledParam = getFormParam(body, "enabled");
	const bool enabled = (enabledParam == "1" || enabledParam == "true" || enabledParam == "on");
	const std::string routeParam = getFormParam(body, "route");

	char* endp = nullptr;
	const unsigned long parsedRoute = routeParam.empty() ? 0 : std::strtoul(routeParam.c_str(), &endp, 10);
	if (!routeParam.empty() && (endp == nullptr || *endp != '\0'))
	{
		sendResponse(sock, 400, "Bad Request", "application/json",
		             "{\"error\":\"route must be a slot index\"}");
		return;
	}

	if (RequestsHandler* handler = _handler.load(std::memory_order_acquire))
	{
		std::string err = handler->setSbcMode(enabled, static_cast<size_t>(parsedRoute));
		if (!err.empty())
		{
			sendResponse(sock, 400, "Bad Request", "application/json",
			             "{\"error\":\"" + jsonEscape(err) + "\"}");
			return;
		}
	}
	// Echo the stored result, mirroring sendApiE911Set's pattern above.
	sendApiSbcModeGet(sock);
}

void HttpServer::sendApiDidMappingList(int sock)
{
	std::vector<DidMapping::Entry> mappings;
	if (RequestsHandler* handler = _handler.load(std::memory_order_acquire))
	{
		mappings = handler->getDidMappings();
	}

	std::ostringstream json;
	json << "{\"mappings\":[";
	for (size_t i = 0; i < mappings.size(); ++i)
	{
		if (i > 0) json << ",";
		json << didMappingJson(mappings[i]);
	}
	json << "]}";
	sendResponse(sock, 200, "OK", "application/json", json.str());
}

void HttpServer::sendApiDidMappingSet(int sock, const std::string& body)
{
	// Params: did, extension. The extension is validated with this codebase's
	// EXISTING extension-pattern checks rather than a new one: pbx::isDialTokenSafe
	// (the same charset gate sendApiDialPlan applies to a pattern/target
	// extension, DialPlan.hpp) and the same reserved-virtual-extension set
	// PbxFeatureConfig.cpp's setForwardLocked/setRingGroup/setDialRule already
	// refuse -- 777 (echo test), 999 (all-page), 555 (anchor media bridge), 888
	// (ConferenceRoom meet-me), 440 (busy/reorder tone). None of those are real
	// endpoints a DID could ever usefully ring. `did` itself gets no charset
	// gate here (E.164 DIDs commonly carry a leading '+', which isDialTokenSafe
	// would reject) -- DidMapping::setMapping's own field validation (length +
	// no CR/LF/'=') is the one that applies to it.
	std::string did       = getFormParam(body, "did");
	std::string extension = getFormParam(body, "extension");

	if (did.empty() || extension.empty())
	{
		sendResponse(sock, 400, "Bad Request", "application/json",
		             "{\"error\":\"missing did or extension parameter\"}");
		return;
	}
	if (!pbx::isDialTokenSafe(extension))
	{
		sendResponse(sock, 400, "Bad Request", "application/json",
		             "{\"error\":\"extension may contain only letters, digits, '#' and '*'\"}");
		return;
	}
	if (pbx::isReservedExtension(extension))
	{
		sendResponse(sock, 400, "Bad Request", "application/json",
		             "{\"error\":\"cannot map a DID to a virtual/reserved extension\"}");
		return;
	}
	// Issue #202: a DID pointed at a non-dialable service is an inbound trunk call
	// routed into a name the engine cannot deliver to — the same black hole as a
	// forward, arriving from outside. Refuse the name outright; when a service
	// becomes dialable, this gate opens for it by itself.
	if (pbx::isServiceName(extension) && !pbx::isDialableService(extension))
	{
		sendResponse(sock, 400, "Bad Request", "application/json",
		             "{\"error\":\"cannot map a DID to a service extension that cannot receive calls\"}");
		return;
	}

	if (RequestsHandler* handler = _handler.load(std::memory_order_acquire))
	{
		std::string err = handler->setDidMapping(did, extension);
		if (!err.empty())
		{
			sendResponse(sock, 400, "Bad Request", "application/json",
			             "{\"error\":\"" + jsonEscape(err) + "\"}");
			return;
		}
	}

	sendResponse(sock, 200, "OK", "application/json",
	             "{\"status\":\"ok\",\"did\":\"" + jsonEscape(did) +
	             "\",\"extension\":\"" + jsonEscape(extension) + "\"}");
}

void HttpServer::sendApiDidMappingDelete(int sock, const std::string& body)
{
	std::string did = getFormParam(body, "did");
	if (did.empty())
	{
		sendResponse(sock, 400, "Bad Request", "application/json",
		             "{\"error\":\"missing did parameter\"}");
		return;
	}
	if (RequestsHandler* handler = _handler.load(std::memory_order_acquire))
	{
		// removeMapping() is idempotent -- "" whether or not `did` existed --
		// so there is nothing to branch on here.
		handler->removeDidMapping(did);
	}
	sendResponse(sock, 200, "OK", "application/json",
	             "{\"status\":\"ok\",\"did\":\"" + jsonEscape(did) + "\"}");
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

// Does this request carry a valid admin session? Issue #207.
//
// Deliberately NOT a refactor of requireAdmin's step 2: this answers a question
// without answering the REQUEST. requireAdmin's whole contract is that it writes
// a 401/403 and returns false, which is exactly wrong for an endpoint that must
// still serve an unauthenticated caller and merely wants to know how much to
// include. Reusing it here would turn /api/status into a gated endpoint and break
// the login form it exists to render.
//
// No same-origin check and no CSRF: this gates only what is DISCLOSED on a read,
// and both of those controls are about who can cause an ACTION.
bool HttpServer::hasValidAdminSession(const HttpRequest& req) const
{
	return AdminAuth::validateSession(sessionToken(req));
}

bool HttpServer::requireAdmin(int sock, const HttpRequest& req, bool needCsrf,
	AdminAuth::Role minRole)
{
	// 1. Same-origin. A request with NO Origin header is admitted by design (see
	//    isSameOrigin): curl, native clients and tests/http/test_api.sh do not
	//    send one. That is precisely why step 3 exists — the Origin check is a
	//    browser-only control and cannot stand alone.
	if (!requireSameOrigin(sock, req))
	{
		return false;
	}

	// 2. Session. There is no more "unprovisioned, admit everyone" bypass: the
	//    device ships with a default login credential
	//    (AdminAuth::kDefaultUsername/kDefaultPassword) precisely so this gate
	//    can be unconditional from the very first boot — the old
	//    "open AP until a PIN is set" window (docs/THREAT_MODEL.md §5.1) is
	//    gone.
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

	// 4. Forced initial setup. Until the operator replaces the default login
	//    credential, every admin-gated action except the one that changes it
	//    is refused server-side — "force setup on first use" enforced here,
	//    not left to the frontend to merely suggest.
	if (AdminAuth::needsInitialSetup() && req.path != "/api/admin/set-credential")
	{
		sendResponse(sock, 403, "Forbidden", "application/json",
		             "{\"error\":\"setup_required\",\"message\":\"Change the default admin credential before continuing.\"}");
		return false;
	}

	// 5. Issue #173: owner-only actions. sessionSatisfiesRole() admits a Sysop
	//    session here TOO, but only while no owner credential has ever been
	//    set (the no-owner fallback — see its declaration comment for why:
	//    otherwise every already-deployed single-credential board loses
	//    factory-reset/OTA/the encrypted export block the instant it upgrades
	//    to this firmware, with no owner account yet to grant them back).
	if (minRole == AdminAuth::Role::Owner && !AdminAuth::sessionSatisfiesRole(token, minRole))
	{
		sendResponse(sock, 403, "Forbidden", "application/json",
		             "{\"error\":\"owner privilege required\"}");
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
// urlDecode intentionally does NOT live here. This TU used to carry its own
// file-static copy built on sscanf(substr(pos+1, 2), "%x", &ii), which silently
// diverged from the tested one in UrlEncode.hpp:
//
//   * scanf's %x stops at the first non-hex character and still reports one
//     successful conversion, so "%5g" decoded to byte 0x05 AND swallowed the
//     'g' via the pos += 2 that followed. UrlEncode.hpp's hexVal() rejects the
//     pair and emits a literal '%', leaving "5g" intact.
//   * %x also accepts a leading sign, so "%-1" parsed rather than being passed
//     through.
//
// Two decoders is one too many: the tested one (tests/UrlEncode_test.cpp,
// UrlDecodeTrailingEscape) was reachable only from TelephonyAnchorClient, while
// every HTML form route -- getFormParam() below, and therefore every admin POST
// -- went through the weaker copy. drawbridge hit the same split and resolved it
// the same way (its audit #73), making the header the single source of truth.

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
	             "{\"networks\":[], \"note\":\"WiFi is not available on this build -- this board has no WiFi radio in its current Ethernet-transport configuration\"}");
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
	             "{\"error\":\"WiFi is not available on this build -- this board has no WiFi radio in its current Ethernet-transport configuration\"}");
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
	             "{\"error\":\"WiFi is not available on this build -- this board has no WiFi radio in its current Ethernet-transport configuration\"}");
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
	// Clear the login credential, the DTMF PIN, and all sessions so the device
	// returns to the default-credential/needs-initial-setup state on both ESP
	// (NVS) and host (in-memory).
	AdminAuth::clearCredential();
	// Also drop ap_secure / ap_psk / cfgseed_gen. Clearing the seed generation is
	// deliberate: the next boot re-applies whatever the flasher wrote, so a
	// factory reset returns the board to how it was FLASHED rather than to a
	// hardcoded default the operator never chose.
	DeviceConfig::clearAll();
	// Also wipe the Telephony-API credential slots ("tapicfg") and the DID ->
	// extension table ("didmap") -- both live in their OWN NVS namespace /
	// host-file specifically so that clearing the device's own settings would NOT
	// collaterally touch them (see TelephonyApiConfig.hpp's and DidMapping.hpp's
	// class comments), which means a factory reset must clear them explicitly or a
	// carrier OAuth client_id/client_secret and the full DID table survive the
	// reset in flash. The CDR call-history ring ("cdrlog") is the same story --
	// its own NVS namespace again, so callers/callees survive a reset unless
	// cleared here too.
	//
	// Nothing else in this function reaches them: DeviceConfig::clearAll() just
	// above erases only its three named "storage" keys plus reg_mode in "pbxcfg"
	// (via that file's eraseRegistrarMode(), src/Helpers/DeviceConfig.cpp), and the
	// WiFi block further down erases four more "storage" keys by name. Both of
	// those are key-by-key, never a namespace wipe, so a namespace no line here
	// names is not reached at all. (An earlier version of this comment said
	// "storage"/"pbxcfg" were erased "above"/"below", which pointed at nothing in
	// this file: those erases live in DeviceConfig.cpp, a different translation
	// unit.)
	//
	// All three are owned by RequestsHandler
	// (_tapiConfig/_didMapping/_cdr), so go through it like every other
	// mutation of those tables. Unconditional (not gated on
	// POCKETDIAL_HAS_WIFI below) so this also runs -- and is host-testable --
	// on eth/desktop builds, matching AdminAuth::clearCredential()/
	// DeviceConfig::clearAll() just above.
	if (RequestsHandler* handler = _handler.load(std::memory_order_acquire))
	{
		handler->clearAllTelephonyConfig();
		handler->clearAllDidMappings();
		handler->clearAllCallHistory();
	}
	// ── Issue #194 Stage 1 DECISION: factory reset ALSO wipes the SD CDR
	// archive, same policy as the NVS ring immediately above. This device
	// already treats call history (caller/callee, when, how long) as
	// sensitive as carrier credentials -- that is the entire reason
	// clearAllCallHistory() exists as its own explicit step rather than
	// falling out of DeviceConfig::clearAll(). An SD file does not
	// automatically inherit that policy just because it holds the same data:
	// without this call, a factory reset would erase the live NVS ring while
	// leaving a full, dated, plaintext history sitting on the card, which is
	// almost certainly the more surprising and worse outcome of the two for
	// an operator who just asked the device to forget everything. If a
	// deployment wants the SD archive to OUTLIVE a factory reset instead
	// (e.g. the archive is the compliance record and the reset is routine
	// re-provisioning), that is a one-line reversal at this call site -- flag
	// it in review if this default is wrong for how pocket-dial is actually
	// deployed.
	//
	// Called directly here, NOT threaded through clearAllCallHistory(): that
	// method takes RequestsHandler::_mutex, and directory I/O (opendir/
	// unlink) must never run while holding it -- see CdrArchive.hpp's SD
	// write-discipline note. sendApiFactoryReset() runs on the HTTP task with
	// no lock held, the same context the MoH-upload fopen() above already
	// uses, so calling it here is safe. No-op on every build without an SD
	// archive installed (see cdrarchive::wipeAll()'s doc comment).
	cdrarchive::wipeAll();
	//
	// The DTMF admin menu's OWN factory-reset path (*<PIN>#999#1,
	// DtmfFeatureCodes.cpp) does not call this function -- it runs
	// nvs_flash_erase() + esp_restart() directly on the SIP thread, which wipes
	// NVS more thoroughly than the targeted erases here. Since issue #222 it
	// ALSO calls cdrarchive::wipeAll() right before the restart, so both doors
	// forget the same things; the justification for doing file I/O on the SIP
	// thread in that one spot (the thread is about to be rebooted out of
	// existence) lives at that call site. If the "what does a factory reset
	// wipe" policy changes here, change it there too -- DtmfFactoryReset_test.cpp
	// pins the DTMF side.
#if defined(POCKETDIAL_HAS_WIFI)
	// The ONLY genuinely radio-specific work in this handler. It stays gated on the
	// transport (not the platform) for a second reason beyond the keys themselves:
	// nvs.h/nvs_flash.h are included under POCKETDIAL_HAS_WIFI alone (top of file),
	// so nothing outside this block may touch NVS directly.
	nvs_handle_t nvs_handle;
	if (nvs_open("storage", NVS_READWRITE, &nvs_handle) == ESP_OK) {
		nvs_erase_key(nvs_handle, "wifi_mode");
		nvs_erase_key(nvs_handle, "wifi_ssid");
		nvs_erase_key(nvs_handle, "wifi_pass");
		nvs_erase_key(nvs_handle, "decayed");
		nvs_commit(nvs_handle);
		nvs_close(nvs_handle);
	}
#endif
	// Every build that reaches this line has completed the wipe above, so every
	// build has to say so. This used to answer 200 only under POCKETDIAL_HAS_WIFI
	// and drop eth/lan8720 into a 501 "factory reset not available on desktop" --
	// on real hardware, after the credential, the carrier OAuth secret, the DID
	// table and the CDR ring were already gone. An operator reading that reasonably
	// concludes nothing happened. Report the outcome truthfully everywhere; only
	// the follow-up instruction differs, because only the radio builds come back to
	// a captive portal.
#if defined(POCKETDIAL_HAS_WIFI)
	sendResponse(sock, 200, "OK", "application/json",
	             "{\"status\":\"ok\",\"message\":\"Factory reset. Rebooting to captive-portal setup...\"}");
#elif defined(ESP_PLATFORM)
	// Wired boards have no captive portal: they reboot straight back to the
	// dashboard, which reports needsSetup:true and demands a new admin login
	// before the SIP registrar will start.
	sendResponse(sock, 200, "OK", "application/json",
	             "{\"status\":\"ok\",\"message\":\"Factory reset. Rebooting \\u2014 the dashboard will ask you to create a new admin login.\"}");
#else
	// Genuine desktop/host build: the wipe succeeded, there is simply no firmware
	// to restart. This is the one case the old 501 described correctly, and even
	// here it was the wrong status for an operation that did complete.
	sendResponse(sock, 200, "OK", "application/json",
	             "{\"status\":\"ok\",\"message\":\"Factory reset. Restart the process to complete.\"}");
#endif
#if defined(ESP_PLATFORM)
	// Guarded on the platform, not the transport: esp_restart() and the deferred
	// restart task exist on every ESP build (see the include block at the top of
	// this file, which already makes exactly this distinction for the OTA path).
	xTaskCreate([](void*) {
		vTaskDelay(pdMS_TO_TICKS(1000));
		esp_restart();
	}, "restart_task", 2048, NULL, 5, NULL);
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
	bool authenticated = isAuthed(req);   // slides the session's expiry (existing behavior)
	// Read the remaining TTL AFTER isAuthed()'s validateSession() has already
	// applied its own slide above — this call adds no slide of its own, so a
	// dashboard polling this endpoint just to show a countdown doesn't distort
	// the number it displays beyond what isAuthed() itself already causes.
	uint64_t sessionRemainingMs = 0;
	AdminAuth::Role role = AdminAuth::Role::None;
	if (authenticated)
	{
		sessionRemainingMs = AdminAuth::sessionRemainingMs(cookieValue(req, "pd_session"));
		role = AdminAuth::sessionRole(cookieValue(req, "pd_session"));
	}
	// Issue #173: `role`/`ownerProvisioned` let the dashboard show or hide the
	// owner-only actions (factory reset, export-with-secrets, OTA upload) and
	// the "create the owner account" prompt without probing each one.
	// `role` is "" (not "none") while unauthenticated -- unauthenticated
	// already has its own boolean field, so a caller doesn't need to parse a
	// string to learn it.
	std::ostringstream json;
	json << "{\"provisioned\":" << (provisioned ? "true" : "false")
	     << ",\"needsSetup\":" << (provisioned ? "false" : "true")
	     << ",\"authenticated\":" << (authenticated ? "true" : "false")
	     << ",\"role\":\"" << (role == AdminAuth::Role::Owner ? "owner" :
	                            role == AdminAuth::Role::Sysop ? "sysop" : "")
	     << "\",\"ownerProvisioned\":" << (AdminAuth::isOwnerProvisioned() ? "true" : "false")
	     << ",\"sessionRemainingSec\":" << (sessionRemainingMs / 1000) << "}";
	sendResponse(sock, 200, "OK", "application/json", json.str());
}

void HttpServer::sendApiAdminSetOwnerCredential(int sock, const HttpRequest& req)
{
	// Reached only through requireAdmin(..., minRole=Owner) -- which, via
	// sessionSatisfiesRole()'s no-owner-yet fallback, means either a real
	// owner session (replacing an existing owner credential) or a sysop
	// session on a device with NO owner yet (bootstrapping the first one).
	std::string username = getFormParam(req.body, "ownerUsername");
	std::string password = getFormParam(req.body, "ownerPassword");

	if (username.empty() || password.empty())
	{
		sendResponse(sock, 400, "Bad Request", "application/json",
		             "{\"error\":\"ownerUsername and ownerPassword are both required\"}");
		return;
	}
	if (!AdminAuth::setOwnerCredential(username, password))
	{
		sendResponse(sock, 400, "Bad Request", "application/json",
		             "{\"error\":\"invalid owner username/password, or it collides with the sysop username\"}");
		return;
	}

	sendResponse(sock, 200, "OK", "application/json",
	             "{\"status\":\"ok\",\"ownerProvisioned\":true}");
}

void HttpServer::sendApiAdminSetCredential(int sock, const HttpRequest& req)
{
	// Reached only with a valid session (requireAdmin) — either an operator
	// still on the default credential doing forced initial setup, or one
	// changing an already-real credential/DTMF PIN later. `username`+`password`
	// must arrive together (a credential needs both); an empty `dtmfPin` means
	// "leave the DTMF PIN as it is", same "empty means keep existing" contract
	// TelephonyApiConfig's secret field already uses.
	std::string username = getFormParam(req.body, "username");
	std::string password = getFormParam(req.body, "password");
	std::string dtmfPin  = getFormParam(req.body, "dtmfPin");

	bool changedLogin = false;
	bool changedPin = false;

	if (!username.empty() || !password.empty())
	{
		if (username.empty() || password.empty())
		{
			sendResponse(sock, 400, "Bad Request", "application/json",
			             "{\"error\":\"username and password must both be provided together\"}");
			return;
		}
		if (!AdminAuth::setLoginCredential(username, password))
		{
			sendResponse(sock, 400, "Bad Request", "application/json",
			             "{\"error\":\"invalid username or password\"}");
			return;
		}
		changedLogin = true;
	}

	if (!dtmfPin.empty())
	{
		// Issue #173 (found in review, not in the original issue text): the
		// DTMF admin menu's *999#1 code wipes the ENTIRE NVS flash
		// (nvs_flash_erase(), DtmfFeatureCodes.cpp) — including the owner
		// credential itself. Without this gate, a sysop session could set a
		// DTMF PIN here, dial *<PIN>999#1 from any registered phone to
		// factory-reset the device, and land back on a no-owner-yet board
		// where sessionSatisfiesRole()'s fallback hands sysop owner powers
		// again — a sysop-reachable path to permanently escalating past the
		// owner they were never supposed to be able to remove. Gating this
		// at Owner (with the SAME no-owner-yet fallback every other
		// owner-gated action uses) closes it while leaving first-boot
		// onboarding untouched: before any owner exists, the fallback still
		// lets the sysop doing initial setup set a DTMF PIN.
		if (!AdminAuth::sessionSatisfiesRole(sessionToken(req), AdminAuth::Role::Owner))
		{
			sendResponse(sock, 403, "Forbidden", "application/json",
			             "{\"error\":\"owner privilege required to set the DTMF admin PIN\"}");
			return;
		}
		if (!AdminAuth::setDtmfPin(dtmfPin))
		{
			sendResponse(sock, 400, "Bad Request", "application/json",
			             "{\"error\":\"DTMF PIN must be 4-16 digits\"}");
			return;
		}
		changedPin = true;
	}

	if (!changedLogin && !changedPin)
	{
		sendResponse(sock, 400, "Bad Request", "application/json",
		             "{\"error\":\"nothing to change\"}");
		return;
	}

	std::ostringstream json;
	json << "{\"status\":\"ok\",\"provisioned\":" << (AdminAuth::isProvisioned() ? "true" : "false")
	     << ",\"needsSetup\":" << (AdminAuth::needsInitialSetup() ? "true" : "false") << "}";
	sendResponse(sock, 200, "OK", "application/json", json.str());
}

void HttpServer::sendApiAdminLogin(int sock, const HttpRequest& req)
{
	std::string username = getFormParam(req.body, "username");
	std::string password = getFormParam(req.body, "password");

	// Reject while locked out before doing any hashing work. Accounting is keyed
	// on (peer address, principal resolved from `username`) — issue #173 — so
	// spraying one principal's password cannot lock the OTHER principal out,
	// and a spoofed source only ever buys the spoofer their own fresh bucket
	// either way (docs/THREAT_MODEL.md D-3).
	if (AdminAuth::isLockedOutForAuth(username, req.clientIp))
	{
		sendResponse(sock, 429, "Too Many Requests", "application/json",
		             "{\"error\":\"too many failed attempts; try again later\"}");
		return;
	}

	AdminAuth::Role role = AdminAuth::authenticate(username, password, req.clientIp);
	if (role == AdminAuth::Role::None)
	{
		// authenticate() may have just engaged the lockout on this attempt.
		if (AdminAuth::isLockedOutForAuth(username, req.clientIp))
		{
			sendResponse(sock, 429, "Too Many Requests", "application/json",
			             "{\"error\":\"too many failed attempts; try again later\"}");
		}
		else
		{
			sendResponse(sock, 401, "Unauthorized", "application/json",
			             "{\"error\":\"invalid username or password\"}");
		}
		return;
	}

	std::string token = AdminAuth::createSession(role);
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
	// instead of needing a full reload to pick the token up. needsSetup tells
	// the frontend whether this login just authenticated with the default
	// credential — if so, requireAdmin() will refuse everything except
	// /api/admin/set-credential until that's fixed, so the page must route
	// straight to the setup form rather than the normal dashboard. `role`
	// (issue #173) lets the dashboard show/hide the owner-only actions
	// without probing each one to find out.
	std::ostringstream json;
	json << "{\"status\":\"ok\",\"authenticated\":true,\"needsSetup\":"
	     << (AdminAuth::needsInitialSetup() ? "true" : "false")
	     << ",\"role\":\"" << (role == AdminAuth::Role::Owner ? "owner" : "sysop") << "\""
	     << ",\"csrf\":\"" << jsonEscape(AdminAuth::sessionCsrf(token)) << "\"}";
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

// ── Config export/import (issue #186) ─────────────────────────────────────
namespace
{
	std::string toHexLocal(const uint8_t* data, size_t len)
	{
		static const char* d = "0123456789abcdef";
		std::string out;
		out.reserve(len * 2);
		for (size_t i = 0; i < len; ++i)
		{
			out.push_back(d[(data[i] >> 4) & 0xF]);
			out.push_back(d[data[i] & 0xF]);
		}
		return out;
	}

	// Decodes a hex string into bytes. Returns false (leaving `out`
	// untouched) on an odd length or any non-hex character -- never silently
	// truncates or skips malformed input, the same discipline UrlEncode.hpp's
	// hexVal() already established for this codebase's other hex/percent
	// decoder.
	bool fromHexLocal(const std::string& hex, std::vector<uint8_t>& out)
	{
		if (hex.size() % 2 != 0) return false;
		std::vector<uint8_t> bytes(hex.size() / 2);
		for (size_t i = 0; i < bytes.size(); ++i)
		{
			auto nibble = [](char c) -> int {
				if (c >= '0' && c <= '9') return c - '0';
				if (c >= 'a' && c <= 'f') return c - 'a' + 10;
				if (c >= 'A' && c <= 'F') return c - 'A' + 10;
				return -1;
			};
			int hi = nibble(hex[2 * i]);
			int lo = nibble(hex[2 * i + 1]);
			if (hi < 0 || lo < 0) return false;
			bytes[i] = static_cast<uint8_t>((hi << 4) | lo);
		}
		out = std::move(bytes);
		return true;
	}
}

// Builds the full export blob. `withSecrets` selects whether the encrypted
// "secretsEnc" block is included; `password` is ignored when it is not.
//
// DATA-SOURCE DISCIPLINE (matches every other sendApi* handler in this file):
// every field below comes from an EXISTING public accessor on DialPlan/
// TelephonyApiConfig/DidMapping/AdminAuth/DeviceConfig/RequestsHandler/
// SipSecretStore -- no new method was added to RequestsHandler.hpp/.cpp for
// this feature (that file is being touched by other concurrent work). Three
// real gaps fell out of that constraint, and are surfaced here rather than
// hidden:
//
//   1. Per-extension digest secrets (SipSecretStore::getHa1) and MAC bindings
//      (RequestsHandler::getAdoptedDevices) export cleanly but have NO way
//      back in: SipSecretStore exposes setSecret(ext, PLAINTEXT) but no
//      "install this HA1 directly" setter, and there is no adoptDevice(mac,
//      ext, state)-shaped mutator at all. sendApiConfigImport() reports both
//      as "skipped" rather than silently dropping them.
//   2. A TelephonyApiConfig slot's actual secret is masked by SlotView
//      (secretSet only) with no accessor that would reverse that -- the
//      gated block below carries baseUrl/clientId/routeDn per slot, never
//      the secret. An operator restoring a trunk config re-enters that one
//      field once, same as fresh setup.
//   3. mDNS hostname (POCKETDIAL_HOSTNAME) and the park-call timeout
//      (POCKETDIAL_PARK_TIMEOUT_SEC) are compile-time constants in this
//      codebase today, not NVS-backed settings -- included as informational
//      plaintext fields so a restored device's operator can see what the
//      backed-up device was running under; import is a no-op for both.
//
// Followup filed in the PR description: an adoptDevice()/setHa1() pair on
// RequestsHandler/SipSecretStore, and a masked-secret round trip for
// TelephonyApiConfig slots, would close gaps 1 and 2 without ever exposing a
// plaintext secret over this API.
void HttpServer::sendApiConfigExport(int sock, bool withSecrets, const std::string& password)
{
	RequestsHandler* handler = _handler.load(std::memory_order_acquire);

	std::ostringstream pt;
	pt << "{";

	// Extensions + MAC bindings (always-plaintext per #186's field list).
	// EXPORT ONLY -- see gap 1 above.
	pt << "\"extensions\":[";
	{
		bool first = true;
		if (handler)
		{
			for (const auto& d : handler->getAdoptedDevices())
			{
				if (!first) pt << ",";
				first = false;
				pt << "{\"mac\":\"" << jsonEscape(d.mac)
				   << "\",\"extension\":\"" << jsonEscape(d.extension)
				   << "\",\"state\":\""
				   << ((d.state == RequestsHandler::DeviceState::Secured) ? "secured" : "learned")
				   << "\"}";
			}
		}
	}
	pt << "],";

	// Per-extension digest secrets (HA1 -- see SipSecretStore.hpp: this IS
	// the persisted, plaintext-equivalent secret; there is no separate
	// original password stored anywhere to export instead). Matches #186's
	// field list verbatim ("per-extension digest secrets" is named as an
	// always-plaintext field). EXPORT ONLY -- see gap 1 above.
	pt << "\"extensionSecrets\":[";
	{
		bool first = true;
		for (const auto& ext : SipSecretStore::securedExtensions())
		{
			auto ha1 = SipSecretStore::getHa1(ext);
			if (!ha1.has_value()) continue;
			if (!first) pt << ",";
			first = false;
			pt << "{\"extension\":\"" << jsonEscape(ext)
			   << "\",\"ha1\":\"" << jsonEscape(*ha1) << "\"}";
		}
	}
	pt << "],";

	pt << "\"ringGroups\":[";
	{
		bool first = true;
		if (handler)
		{
			for (const auto& g : handler->getRingGroups())
			{
				if (!first) pt << ",";
				first = false;
				pt << "{\"extension\":\"" << jsonEscape(std::get<0>(g))
				   << "\",\"mode\":\"" << jsonEscape(std::get<1>(g))
				   << "\",\"members\":\"" << jsonEscape(std::get<2>(g)) << "\"}";
			}
		}
	}
	pt << "],";

	pt << "\"forwards\":[";
	{
		bool first = true;
		if (handler)
		{
			for (const auto& f : handler->getForwards())
			{
				if (!first) pt << ",";
				first = false;
				pt << "{\"extension\":\"" << jsonEscape(std::get<0>(f))
				   << "\",\"always\":\"" << jsonEscape(std::get<1>(f))
				   << "\",\"busy\":\"" << jsonEscape(std::get<2>(f))
				   << "\",\"noAnswer\":\"" << jsonEscape(std::get<3>(f)) << "\"}";
			}
		}
	}
	pt << "],";

	pt << "\"dnd\":[";
	{
		bool first = true;
		if (handler)
		{
			for (const auto& ext : handler->getDndExtensions())
			{
				if (!first) pt << ",";
				first = false;
				pt << "\"" << jsonEscape(ext) << "\"";
			}
		}
	}
	pt << "],";

	pt << "\"voicemail\":[";
	{
		bool first = true;
		if (handler)
		{
			for (const auto& ext : handler->getVoicemailExtensions())
			{
				if (!first) pt << ",";
				first = false;
				pt << "\"" << jsonEscape(ext) << "\"";
			}
		}
	}
	pt << "],";

	pt << "\"pageZones\":[";
	{
		bool first = true;
		if (handler)
		{
			for (const auto& z : handler->getPageZones())
			{
				if (!first) pt << ",";
				first = false;
				pt << "{\"zone\":\"" << jsonEscape(z.first)
				   << "\",\"members\":\"" << jsonEscape(z.second) << "\"}";
			}
		}
	}
	pt << "],";

	pt << "\"dialPlan\":[";
	{
		bool first = true;
		if (handler)
		{
			for (const auto& r : handler->getDialRules())
			{
				if (!first) pt << ",";
				first = false;
				pt << "{\"pattern\":\"" << jsonEscape(std::get<0>(r))
				   << "\",\"action\":\"" << jsonEscape(std::get<1>(r))
				   << "\",\"target\":\"" << jsonEscape(std::get<2>(r))
				   << "\",\"stripDigits\":" << std::get<3>(r) << "}";
			}
		}
	}
	pt << "],";

	pt << "\"didMappings\":[";
	{
		bool first = true;
		if (handler)
		{
			for (const auto& e : handler->getDidMappings())
			{
				if (!first) pt << ",";
				first = false;
				pt << "{\"did\":\"" << jsonEscape(e.did)
				   << "\",\"extension\":\"" << jsonEscape(e.extension) << "\"}";
			}
		}
	}
	pt << "],";

	pt << "\"registrarMode\":\""
	   << (handler ? registrarModeName(handler->getRegistrarMode()) : "open") << "\",";

	// Telephony-API slot METADATA only. baseUrl/clientId/routeDn are
	// password-gated (#186: "anchor/trunk base URL, client ID/secret, source
	// DN") -- see the gated block below. The secret itself is never
	// exportable at all, gated or not -- see gap 2 above.
	pt << "\"telephonyConfig\":[";
	{
		bool first = true;
		if (handler)
		{
			auto slots = handler->getTelephonyConfigSlots();
			for (size_t i = 0; i < slots.size(); ++i)
			{
				if (!first) pt << ",";
				first = false;
				pt << "{\"index\":" << i
				   << ",\"type\":\"" << telephonyProviderName(slots[i].type) << "\""
				   << ",\"enabled\":" << (slots[i].enabled ? "true" : "false")
				   << ",\"secretSet\":" << (slots[i].secretSet ? "true" : "false") << "}";
			}
		}
	}
	pt << "],";

	pt << "\"wifiSsid\":\"" << jsonEscape(DeviceConfig::getWifiSsid()) << "\""
	   << ",\"wifiMode\":" << static_cast<int>(DeviceConfig::getWifiMode())
	   << ",\"apSecure\":" << (DeviceConfig::isApSecure() ? "true" : "false") << ",";

	// Informational only -- see gap 3 above; import is a no-op for both.
#ifndef POCKETDIAL_HOSTNAME
#define POCKETDIAL_HOSTNAME "pocketdial"
#endif
	pt << "\"parkTimeoutSec\":" << POCKETDIAL_PARK_TIMEOUT_SEC << ","
	   << "\"mdnsHostname\":\"" << jsonEscape(POCKETDIAL_HOSTNAME) << "\","
	   << "\"schemaVer\":" << DeviceConfig::kSchemaVersion;
	pt << "}";

	const std::string plaintextJson = pt.str();

	std::ostringstream out;
	out << "{\"exportVer\":1,\"plaintext\":" << plaintextJson;

	if (withSecrets)
	{
		std::ostringstream gated;
		gated << "{\"wifiPassword\":\"" << jsonEscape(DeviceConfig::getWifiPassword()) << "\""
		      << ",\"apPsk\":\"" << jsonEscape(DeviceConfig::getApPsk()) << "\""
		      << ",\"telephonyConfig\":[";
		{
			bool first = true;
			if (handler)
			{
				auto slots = handler->getTelephonyConfigSlots();
				for (size_t i = 0; i < slots.size(); ++i)
				{
					if (!first) gated << ",";
					first = false;
					gated << "{\"index\":" << i
					      << ",\"baseUrl\":\"" << jsonEscape(slots[i].baseUrl) << "\""
					      << ",\"clientId\":\"" << jsonEscape(slots[i].clientId) << "\""
					      << ",\"routeDn\":\"" << jsonEscape(slots[i].routeDn) << "\"}";
				}
			}
		}
		gated << "]}";
		const std::string gatedPlaintext = gated.str();

		uint8_t salt[AdminAuth::kKdfSaltBytes];
		uint8_t nonce[AdminAuth::kGcmNonceBytes];
		AdminAuth::secureRandomBytes(salt, sizeof(salt));
		AdminAuth::secureRandomBytes(nonce, sizeof(nonce));

		uint8_t key[AdminAuth::kAesKeyBytes];
		AdminAuth::pbkdf2Sha256(password, salt, sizeof(salt), AdminAuth::kExportKdfIterations,
			key, sizeof(key));

		std::string ct;
		// AAD binds this block to the EXACT plaintext bytes shipped alongside
		// it (byte-for-byte, since `plaintextJson` is written verbatim into
		// `out` above) so the two halves can never be silently recombined
		// from two different exports, or against a tampered plaintext
		// section, without failing authentication on import.
		AdminAuth::aesGcmSeal(key, nonce, plaintextJson, gatedPlaintext, ct);

		out << ",\"secretsEnc\":{\"kdf\":\"pbkdf2-sha256\""
		    << ",\"iter\":" << AdminAuth::kExportKdfIterations
		    << ",\"salt\":\"" << toHexLocal(salt, sizeof(salt)) << "\""
		    << ",\"nonce\":\"" << toHexLocal(nonce, sizeof(nonce)) << "\""
		    << ",\"ct\":\""
		    << toHexLocal(reinterpret_cast<const uint8_t*>(ct.data()), ct.size()) << "\"}";
	}

	out << "}";
	sendResponse(sock, 200, "OK", "application/json", out.str());
}

// Restores config from an export blob. Body: form-encoded
// blob=<url-encoded export JSON>&password=<optional>&confirm=REPLACE.
//
// Ordering (deliberate): the WHOLE blob is parsed, schema-checked, and (if a
// password was given) decrypted BEFORE any setter runs, so a 400 or 422 here
// leaves every table on the device exactly as it was. Only once everything
// needed has been validated does the apply pass begin, and that pass cannot
// itself fail outward -- each underlying setter already validates and
// silently drops a malformed row (the same "log and drop" contract
// PbxFeatureConfig's setters use for the live HTTP routes), so a partially
// bad blob degrades to a smaller "applied" list rather than a crash.
//
// DEVIATION FROM THE ISSUE TEXT: #186 describes a 204 on success. This
// returns 200 with {"applied":[...],"skipped":[...]} instead -- see gaps 1/2
// on sendApiConfigExport() above: this feature genuinely cannot restore
// everything a plaintext-capable export can carry (MAC bindings, digest
// secrets, a trunk slot's secret), and a bare 204 would tell the operator
// "fully restored" when it was not. Silently dropping those fields would be
// worse than saying so.
void HttpServer::sendApiConfigImport(int sock, const std::string& body)
{
	if (getFormParam(body, "confirm") != "REPLACE")
	{
		// Same "explicit confirm token" convention as /api/factory-reset
		// (confirm=ERASE) -- both are replace-not-merge, both use 400 for a
		// missing/wrong token.
		sendResponse(sock, 400, "Bad Request", "application/json",
		             "{\"error\":\"import requires confirm=REPLACE\"}");
		return;
	}

	const std::string blob = getFormParam(body, "blob");
	const std::string password = getFormParam(body, "password");
	if (blob.empty())
	{
		sendResponse(sock, 400, "Bad Request", "application/json",
		             "{\"error\":\"missing blob parameter\"}");
		return;
	}

	JsonReader::Value root;
	std::string parseErr;
	if (!JsonReader::parse(blob, root, parseErr) || !root.isObject())
	{
		sendResponse(sock, 400, "Bad Request", "application/json",
		             "{\"error\":\"malformed export blob\"}");
		return;
	}
	const JsonReader::Value* pt = root.find("plaintext");
	if (!pt || !pt->isObject())
	{
		sendResponse(sock, 400, "Bad Request", "application/json",
		             "{\"error\":\"export blob is missing a plaintext object\"}");
		return;
	}
	if (root.intOr("exportVer", 1) != 1)
	{
		// Found in review: emitted on export, never checked on import. A
		// future export format bump must not be silently misread as v1 --
		// refuse rather than guess.
		sendResponse(sock, 400, "Bad Request", "application/json",
		             "{\"error\":\"unsupported exportVer\"}");
		return;
	}

	// Decrypt the gated block FIRST (before any setter runs) -- see the
	// function comment on why. A tag mismatch is reported as 422 and is
	// deliberately indistinguishable from a wrong password (AdminAuth::
	// aesGcmOpen's contract): the two must look the same to the caller.
	bool haveSecrets = false;
	JsonReader::Value secretsValue;
	const JsonReader::Value* secretsEncNode = root.find("secretsEnc");
	if (secretsEncNode && secretsEncNode->isObject() && !password.empty())
	{
		std::vector<uint8_t> salt, nonce, ct;
		int iter = secretsEncNode->intOr("iter", 0);
		// Found in review: `iter` is attacker-controlled (a sysop-crafted
		// blob, or any operator on the LAN once past the sysop-level import
		// gate). PBKDF2 cost is linear in it, on the HTTP handler thread --
		// an unbounded value pins that thread for as long as the caller
		// likes. Cap generously above this feature's own iteration count
		// (kExportKdfIterations) rather than pinning it exactly, so a blob
		// exported by an older/newer build with a different constant still
		// imports.
		bool shapeOk = iter > 0 && iter <= static_cast<int>(2 * AdminAuth::kExportKdfIterations) &&
			fromHexLocal(secretsEncNode->stringOr("salt"), salt) &&
			salt.size() == AdminAuth::kKdfSaltBytes &&
			fromHexLocal(secretsEncNode->stringOr("nonce"), nonce) &&
			nonce.size() == AdminAuth::kGcmNonceBytes &&
			fromHexLocal(secretsEncNode->stringOr("ct"), ct) &&
			ct.size() >= AdminAuth::kGcmTagBytes;
		if (!shapeOk)
		{
			sendResponse(sock, 400, "Bad Request", "application/json",
			             "{\"error\":\"malformed secretsEnc block\"}");
			return;
		}

		uint8_t key[AdminAuth::kAesKeyBytes];
		AdminAuth::pbkdf2Sha256(password, salt.data(), salt.size(),
			static_cast<uint32_t>(iter), key, sizeof(key));

		const std::string ctStr(reinterpret_cast<const char*>(ct.data()), ct.size());
		const std::string aad = blob.substr(pt->spanStart, pt->spanEnd - pt->spanStart);
		std::string plaintextOut;
		if (!AdminAuth::aesGcmOpen(key, nonce.data(), aad, ctStr, plaintextOut))
		{
			sendResponse(sock, 422, "Unprocessable Entity", "application/json",
			             "{\"error\":\"bad password or corrupted secrets block\"}");
			return;
		}

		std::string innerErr;
		if (!JsonReader::parse(plaintextOut, secretsValue, innerErr) || !secretsValue.isObject())
		{
			sendResponse(sock, 400, "Bad Request", "application/json",
			             "{\"error\":\"decrypted secrets block is not valid JSON\"}");
			return;
		}
		haveSecrets = true;
	}

	// ── Validated. Apply. ────────────────────────────────────────────────
	RequestsHandler* handler = _handler.load(std::memory_order_acquire);
	std::vector<std::string> applied;
	std::vector<std::string> skipped;

	if (!pt->arrayOr("extensions").empty())
	{
		skipped.push_back("extensions (MAC bindings: no import accessor -- see PR description)");
	}
	if (!pt->arrayOr("extensionSecrets").empty())
	{
		skipped.push_back("extensionSecrets (digest secrets: no import accessor -- see PR description)");
	}

	if (handler)
	{
		// Ring groups: delete-then-set sweep (replace, not merge).
		{
			std::set<std::string> keep;
			for (const auto& g : pt->arrayOr("ringGroups")) keep.insert(g.stringOr("extension"));
			for (const auto& g : handler->getRingGroups())
			{
				if (!keep.count(std::get<0>(g)))
				{
					handler->setRingGroup(std::get<0>(g), "", std::get<1>(g));
				}
			}
			for (const auto& g : pt->arrayOr("ringGroups"))
			{
				handler->setRingGroup(g.stringOr("extension"), g.stringOr("members"),
					g.stringOr("mode", "ringall"));
			}
		}
		applied.push_back("ringGroups");

		// Forwards: replace per (extension, trigger).
		{
			std::set<std::string> keep;
			for (const auto& f : pt->arrayOr("forwards")) keep.insert(f.stringOr("extension"));
			for (const auto& f : handler->getForwards())
			{
				if (!keep.count(std::get<0>(f)))
				{
					handler->setForward(std::get<0>(f), "always", "");
					handler->setForward(std::get<0>(f), "busy", "");
					handler->setForward(std::get<0>(f), "noanswer", "");
				}
			}
			for (const auto& f : pt->arrayOr("forwards"))
			{
				const std::string ext = f.stringOr("extension");
				handler->setForward(ext, "always", f.stringOr("always"));
				handler->setForward(ext, "busy", f.stringOr("busy"));
				handler->setForward(ext, "noanswer", f.stringOr("noAnswer"));
			}
		}
		applied.push_back("forwards");

		// DND: replace membership.
		{
			std::set<std::string> keep;
			for (const auto& d : pt->arrayOr("dnd")) if (d.isString()) keep.insert(d.strVal);
			for (const auto& ext : handler->getDndExtensions())
			{
				if (!keep.count(ext)) handler->setDnd(ext, false);
			}
			for (const auto& ext : keep) handler->setDnd(ext, true);
		}
		applied.push_back("dnd");

		// Voicemail (Issue #246): replace membership, same shape as DND.
		{
			std::set<std::string> keep;
			for (const auto& v : pt->arrayOr("voicemail")) if (v.isString()) keep.insert(v.strVal);
			for (const auto& ext : handler->getVoicemailExtensions())
			{
				if (!keep.count(ext)) handler->setVoicemail(ext, false);
			}
			for (const auto& ext : keep) handler->setVoicemail(ext, true);
		}
		applied.push_back("voicemail");

		// Page zones: delete-then-set sweep.
		{
			std::set<std::string> keep;
			for (const auto& z : pt->arrayOr("pageZones")) keep.insert(z.stringOr("zone"));
			for (const auto& z : handler->getPageZones())
			{
				if (!keep.count(z.first)) handler->setPageZone(z.first, "");
			}
			for (const auto& z : pt->arrayOr("pageZones"))
			{
				handler->setPageZone(z.stringOr("zone"), z.stringOr("members"));
			}
		}
		applied.push_back("pageZones");

		// Dial plan: delete-then-set sweep. setDialRule() deletes ONLY when
		// BOTH action and target are empty (PbxFeatureConfig::setDialRule) --
		// an empty target alone means "trunk: prepend nothing" and must not
		// be read as a delete.
		{
			std::set<std::string> keep;
			for (const auto& r : pt->arrayOr("dialPlan")) keep.insert(r.stringOr("pattern"));
			for (const auto& r : handler->getDialRules())
			{
				if (!keep.count(std::get<0>(r)))
				{
					handler->setDialRule(std::get<0>(r), "", "", 0);
				}
			}
			for (const auto& r : pt->arrayOr("dialPlan"))
			{
				handler->setDialRule(r.stringOr("pattern"), r.stringOr("action"),
					r.stringOr("target"), r.intOr("stripDigits", 0));
			}
		}
		applied.push_back("dialPlan");

		// DID mappings: RequestsHandler exposes a genuine bulk clear (the same
		// one /api/factory-reset uses), unlike the four tables above -- use it
		// for a real replace instead of hand-rolling a diff.
		handler->clearAllDidMappings();
		for (const auto& m : pt->arrayOr("didMappings"))
		{
			handler->setDidMapping(m.stringOr("did"), m.stringOr("extension"));
		}
		applied.push_back("didMappings");

		// Registrar mode: the SAME lockout guard sendApiRegistrarSet() already
		// enforces for a live switch to `secure` -- restoring `secure` onto a
		// device whose extensions could NOT be restored (see the
		// extensions/extensionSecrets skip above) would digest-challenge every
		// REGISTER with no working handset left to notice. Every other mode
		// applies outright.
		RequestsHandler::RegistrarMode parsedMode;
		if (parseRegistrarMode(pt->stringOr("registrarMode", "open"), parsedMode))
		{
			if (parsedMode == RequestsHandler::RegistrarMode::Secure)
			{
				size_t secured = 0;
				for (const auto& d : handler->getAdoptedDevices())
				{
					if (d.state == RequestsHandler::DeviceState::Secured) ++secured;
				}
				if (secured == 0)
				{
					skipped.push_back("registrarMode=secure (no extensions are secured on "
						"this device yet -- would lock out every phone; switch manually "
						"once extensions are re-provisioned)");
				}
				else
				{
					handler->setRegistrarMode(parsedMode);
					applied.push_back("registrarMode");
				}
			}
			else
			{
				handler->setRegistrarMode(parsedMode);
				applied.push_back("registrarMode");
			}
		}

		// Telephony-config metadata (type/enabled only -- baseUrl/clientId/
		// routeDn are gated, applied further below if a password was given).
		// keepSecret=true always: the plaintext half never carries the
		// secret, so this pass must never clear an existing one.
		for (const auto& slot : pt->arrayOr("telephonyConfig"))
		{
			int idxI = slot.intOr("index", -1);
			if (idxI < 0) continue;
			size_t idx = static_cast<size_t>(idxI);
			TelephonyApiConfig::SlotView existing = handler->getTelephonyConfigSlot(idx);
			TelephonyApiConfig::Slot s;
			s.type = existing.type;
			s.enabled = slot.boolOr("enabled", existing.enabled);
			s.baseUrl = existing.baseUrl;
			s.clientId = existing.clientId;
			s.routeDn = existing.routeDn;
			handler->setTelephonyConfigSlot(idx, s, /*keepSecret=*/true);
		}
		applied.push_back("telephonyConfig (metadata)");
	}
	else
	{
		skipped.push_back("SIP engine not attached yet -- ring groups/forwards/dnd/voicemail/pageZones/"
			"dialPlan/didMappings/registrarMode/telephonyConfig not applied");
	}

	// WiFi SSID/mode + the AP-secure toggle: plaintext, always applied.
	const std::string ssid = pt->stringOr("wifiSsid");
	if (!ssid.empty())
	{
		// Found in review: the range check belongs BEFORE the narrowing cast.
		// A raw value like 258 wraps to a perfectly in-range uint8_t (2) and
		// would silently pass DeviceConfig::setWifiConfig()'s own `mode > 2`
		// check despite being nonsense on the wire.
		const int rawMode = pt->intOr("wifiMode", 0);
		if (rawMode < 0 || rawMode > 2)
		{
			skipped.push_back("wifiSsid/wifiMode (mode out of range)");
		}
		else if (DeviceConfig::setWifiConfig(ssid, static_cast<uint8_t>(rawMode)))
		{
			applied.push_back("wifiSsid/wifiMode");
		}
		else
		{
			skipped.push_back("wifiSsid/wifiMode (invalid)");
		}
	}
	DeviceConfig::setApSecure(pt->boolOr("apSecure", DeviceConfig::isApSecure()));
	applied.push_back("apSecure");

	// Password-gated fields, only once the block above actually decrypted.
	if (haveSecrets)
	{
		DeviceConfig::setWifiPassword(secretsValue.stringOr("wifiPassword"));
		applied.push_back("wifiPassword");

		const std::string apPsk = secretsValue.stringOr("apPsk");
		if (!apPsk.empty())
		{
			if (DeviceConfig::setApPsk(apPsk)) applied.push_back("apPsk");
			else skipped.push_back("apPsk (invalid passphrase)");
		}

		if (handler)
		{
			for (const auto& slot : secretsValue.arrayOr("telephonyConfig"))
			{
				int idxI = slot.intOr("index", -1);
				if (idxI < 0) continue;
				size_t idx = static_cast<size_t>(idxI);
				TelephonyApiConfig::SlotView existing = handler->getTelephonyConfigSlot(idx);
				TelephonyApiConfig::Slot s;
				s.type = existing.type;
				s.enabled = existing.enabled;
				s.baseUrl = slot.stringOr("baseUrl");
				s.clientId = slot.stringOr("clientId");
				s.routeDn = slot.stringOr("routeDn");
				// keepSecret=true: the export never carries the actual secret
				// (SlotView masks it -- see gap 2 in sendApiConfigExport's
				// comment). An operator restoring a trunk config re-enters
				// that one field once, same as fresh setup.
				handler->setTelephonyConfigSlot(idx, s, /*keepSecret=*/true);
			}
			applied.push_back("telephonyConfig (baseUrl/clientId/routeDn)");
		}
	}
	else if (secretsEncNode)
	{
		skipped.push_back(password.empty()
			? "secretsEnc present but no password supplied"
			: "secretsEnc present but not applied");
	}

	std::ostringstream json;
	json << "{\"status\":\"ok\",\"applied\":[";
	for (size_t i = 0; i < applied.size(); ++i)
	{
		if (i) json << ",";
		json << "\"" << jsonEscape(applied[i]) << "\"";
	}
	json << "],\"skipped\":[";
	for (size_t i = 0; i < skipped.size(); ++i)
	{
		if (i) json << ",";
		json << "\"" << jsonEscape(skipped[i]) << "\"";
	}
	json << "]}";
	sendResponse(sock, 200, "OK", "application/json", json.str());
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

void HttpServer::sendApiSyslogStatus(int sock)
{
	// The host is reported back; there is no secret here (a collector address is
	// not a credential), and an operator needs to see what the board thinks it is
	// pointed at to debug 'why am I getting no logs'.
	std::ostringstream json;
	json << "{\"supported\":"
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	     << "true"
#else
	     << "false"
#endif
	     << ",\"enabled\":" << (Syslog::isConfigured() ? "true" : "false")
	     << ",\"host\":\"" << jsonEscape(Syslog::configuredHost())
	     << "\",\"port\":" << Syslog::configuredPort()
	     << "}";
	sendResponse(sock, 200, "OK", "application/json", json.str());
}

void HttpServer::sendApiSyslogSet(int sock, const std::string& body)
{
	const std::string host = getFormParam(body, "host");
	const std::string portStr = getFormParam(body, "port");

	// Default 514 when omitted; an explicit out-of-range value is an error rather
	// than something to silently clamp, because a clamped port fails later as a
	// mysterious absence of logs.
	long port = 514;
	if (!portStr.empty())
	{
		char* end = nullptr;
		port = std::strtol(portStr.c_str(), &end, 10);
		if (end == portStr.c_str() || *end != '\0' || port < 1 || port > 65535)
		{
			sendResponse(sock, 400, "Bad Request", "application/json",
			             "{\"error\":\"port must be 1-65535\"}");
			return;
		}
	}

	// An empty host is the documented way to turn remote logging off, so it is a
	// success, not a validation failure.
	if (!Syslog::saveToNvs(host, static_cast<uint16_t>(port)))
	{
		sendResponse(sock, 400, "Bad Request", "application/json",
		             "{\"error\":\"host must be a dotted-quad IPv4 address (no DNS resolver on this device), or empty to disable\"}");
		return;
	}

	sendResponse(sock, 200, "OK", "application/json",
	             host.empty()
	               ? "{\"status\":\"ok\",\"message\":\"remote logging disabled\"}"
	               : "{\"status\":\"ok\",\"message\":\"remote logging enabled\"}");
}

// ---------------------------------------------------------------------
// Issue #159: SMTP client config + test-send. See EmailConfigStore.hpp for
// the persisted shape, SmtpDialogue.hpp/SmtpClient.hpp for the send itself.
// ---------------------------------------------------------------------
namespace
{
	SmtpDialogue::Mode emailModeFromString(const std::string& s)
	{
		if (s == "tls") return SmtpDialogue::Mode::ImplicitTls;
		if (s == "plain") return SmtpDialogue::Mode::Plain;
		return SmtpDialogue::Mode::StartTls; // "starttls", default, and any unrecognised value
	}
	// Validates the raw string form BEFORE it is folded into the fallback
	// case above -- so "auth=bogus" is a 400, not silently stored as "none".
	bool isValidEmailMode(const std::string& s) { return s == "tls" || s == "starttls" || s == "plain"; }
	bool isValidEmailAuth(const std::string& s)
	{
		return s == "none" || s == "plain" || s == "login" || s == "xoauth2-sa";
	}
	SmtpDialogue::AuthMethod emailAuthFromString(const std::string& s)
	{
		if (s == "plain") return SmtpDialogue::AuthMethod::Plain;
		if (s == "login") return SmtpDialogue::AuthMethod::Login;
		if (s == "xoauth2-sa") return SmtpDialogue::AuthMethod::XOAuth2;
		return SmtpDialogue::AuthMethod::None;
	}
	uint16_t defaultPortForMode(const std::string& mode)
	{
		if (mode == "tls") return 465;
		if (mode == "plain") return 25;
		return 587;
	}
	std::string emailConfigJson(const EmailConfigStore::Config& cfg)
	{
		std::ostringstream json;
		json << "{\"host\":\"" << jsonEscape(cfg.host) << "\""
		     << ",\"port\":" << cfg.port
		     << ",\"mode\":\"" << jsonEscape(cfg.mode) << "\""
		     << ",\"auth\":\"" << jsonEscape(cfg.auth) << "\""
		     << ",\"user\":\"" << jsonEscape(cfg.user) << "\""
		     << ",\"from\":\"" << jsonEscape(cfg.from) << "\""
		     << ",\"to\":\"" << jsonEscape(cfg.to) << "\""
		     << ",\"gsaEmail\":\"" << jsonEscape(cfg.gsaEmail) << "\""
		     // Secrets: presence only, NEVER the value -- issue #207's class.
		     << ",\"hasPassword\":" << (cfg.pass.empty() ? "false" : "true")
		     << ",\"hasGsaKey\":" << (cfg.gsaKey.empty() ? "false" : "true")
		     << ",\"insecure\":" << (cfg.insecureSkipVerify ? "true" : "false")
		     << ",\"hasCaPem\":" << (cfg.caPem.empty() ? "false" : "true")
		     << "}";
		return json.str();
	}
} // namespace

void HttpServer::sendApiEmailConfig(int sock)
{
	sendResponse(sock, 200, "OK", "application/json", emailConfigJson(EmailConfigStore::load()));
}

void HttpServer::sendApiEmailConfigSet(int sock, const std::string& body)
{
	const std::string mode = getFormParam(body, "mode");
	const std::string auth = getFormParam(body, "auth");
	if (!mode.empty() && !isValidEmailMode(mode))
	{
		sendResponse(sock, 400, "Bad Request", "application/json",
		             "{\"error\":\"mode must be tls, starttls or plain\"}");
		return;
	}
	if (!auth.empty() && !isValidEmailAuth(auth))
	{
		sendResponse(sock, 400, "Bad Request", "application/json",
		             "{\"error\":\"auth must be none, plain, login or xoauth2-sa\"}");
		return;
	}

	EmailConfigStore::Config cfg = EmailConfigStore::load(); // start from what's stored -- see "keep unchanged" below
	cfg.host = getFormParam(body, "host");
	cfg.mode = mode.empty() ? cfg.mode : mode;
	cfg.auth = auth.empty() ? cfg.auth : auth;

	const std::string portStr = getFormParam(body, "port");
	if (portStr.empty())
	{
		cfg.port = defaultPortForMode(cfg.mode);
	}
	else
	{
		char* end = nullptr;
		long port = std::strtol(portStr.c_str(), &end, 10);
		if (end == portStr.c_str() || *end != '\0' || port < 1 || port > 65535)
		{
			sendResponse(sock, 400, "Bad Request", "application/json",
			             "{\"error\":\"port must be 1-65535\"}");
			return;
		}
		cfg.port = static_cast<uint16_t>(port);
	}

	cfg.user = getFormParam(body, "user");
	cfg.from = getFormParam(body, "from");
	cfg.to = getFormParam(body, "to");
	cfg.gsaEmail = getFormParam(body, "gsaEmail");
	const std::string insecureParam = getFormParam(body, "insecure");
	cfg.insecureSkipVerify = (insecureParam == "1" || insecureParam == "on");

	// Secrets: an empty submitted value means "leave the stored one alone" --
	// the dashboard never re-displays a real password/private key to redact
	// FROM, so there is nothing to compare against on the client side, and a
	// blank field must not be read as "clear this". See EmailConfigStore.hpp.
	const std::string pass = getFormParam(body, "pass");
	if (!pass.empty()) cfg.pass = pass;
	const std::string gsaKey = getFormParam(body, "gsaKey");
	if (!gsaKey.empty()) cfg.gsaKey = gsaKey;
	const std::string caPem = getFormParam(body, "caPem");
	if (!caPem.empty()) cfg.caPem = caPem;

	if (!EmailConfigStore::save(cfg))
	{
		sendResponse(sock, 500, "Internal Server Error", "application/json",
		             "{\"error\":\"failed to persist email configuration\"}");
		return;
	}

	sendResponse(sock, 200, "OK", "application/json",
	             "{\"status\":\"ok\",\"config\":" + emailConfigJson(cfg) + "}");
}

void HttpServer::sendApiEmailTest(int sock, const std::string& body)
{
	EmailConfigStore::Config stored = EmailConfigStore::load();
	if (stored.host.empty())
	{
		sendResponse(sock, 200, "OK", "application/json",
		             "{\"ok\":false,\"error\":\"no SMTP host configured -- save the settings above first\"}");
		return;
	}

	std::string to = getFormParam(body, "to");
	if (to.empty()) to = stored.to;
	if (to.empty())
	{
		sendResponse(sock, 200, "OK", "application/json",
		             "{\"ok\":false,\"error\":\"no recipient -- set a default 'to' or pass one to this test\"}");
		return;
	}

	SmtpDialogue::Config cfg;
	cfg.host = stored.host;
	cfg.port = stored.port;
	cfg.mode = emailModeFromString(stored.mode);
	cfg.auth = emailAuthFromString(stored.auth);
	cfg.username = stored.user;
	cfg.password = stored.pass;
	cfg.commandTimeoutMs = 15000;

	// The Workspace service-account path needs a bearer token, but this handler
	// does NOT fetch one. Minting is an RSA-2048 signature plus a full TLS
	// handshake to oauth2.googleapis.com, and this function runs on a
	// per-connection HTTP handler thread -- an IDF pthread on the 8192-byte
	// CONFIG_PTHREAD_TASK_STACK_SIZE_DEFAULT. Every other TLS-handshake path in
	// this codebase runs on a task with a dedicated 12 KB PSRAM stack for
	// exactly that reason (PsramTask.hpp), and SmtpClient's worker is one of
	// them.
	//
	// So the material is handed to the worker and it mints there. That also
	// restores what SmtpClient::sendAndWait()'s contract already promised --
	// "the caller's own thread never does socket/TLS I/O itself" -- which the
	// inline fetch had quietly broken.
	SmtpClient::TokenRequest token;
	if (cfg.auth == SmtpDialogue::AuthMethod::XOAuth2)
	{
		token.serviceAccountEmail = stored.gsaEmail;
		token.subjectUser         = stored.user;
		token.scope               = "https://mail.google.com/";
		token.privateKeyPem       = stored.gsaKey;
	}

	SmtpDialogue::Message msg;
	msg.from = stored.from.empty() ? stored.user : stored.from;
	msg.to = to;
	msg.subject = "pocket-dial test message";
	msg.textBody = "This is a test message from pocket-dial's SMTP client (issue #159).\r\n"
	               "If you can read this, outbound email is configured correctly.\r\n";

	const bool allowPlain = (cfg.mode == SmtpDialogue::Mode::Plain);

	SmtpDialogue::SendResult result;
	// 20 s was sized for the SMTP session alone. A cold XOAUTH2 send now also
	// pays the token mint on the worker (RSA-2048 sign + a TLS handshake to
	// Google, ~1-2 s on this silicon with no ECC accelerator) before the SMTP
	// session even starts, so the budget has to cover both or a first-of-the-hour
	// test would report a spurious Timeout while the send was in fact fine.
	// Cached-token sends are unaffected -- getAccessToken() reuses one until 60 s
	// before expiry.
	const uint32_t waitMs = token.serviceAccountEmail.empty() ? 20000u : 35000u;

	bool dispatched = SmtpClient::sendAndWait(cfg, msg, allowPlain, stored.caPem, stored.insecureSkipVerify,
	                                           waitMs, result, token);

	std::ostringstream json;
	json << "{\"ok\":" << ((dispatched && result.ok()) ? "true" : "false")
	     << ",\"resultCode\":" << static_cast<int>(result.code)
	     << ",\"smtpReplyCode\":" << result.smtpReplyCode
	     << ",\"error\":\"" << jsonEscape(result.lastError) << "\""
	     << "}";
	sendResponse(sock, 200, "OK", "application/json", json.str());
}

void HttpServer::sendEmailSetupHtml(int sock, const HttpRequest& req)
{
	std::string page(PD_HTML_8, sizeof(PD_HTML_8) - 1);
	const std::string token = AdminAuth::sessionCsrf(sessionToken(req));
	const std::string marker = "__PD_CSRF__";
	const size_t at = page.find(marker);
	if (at != std::string::npos)
	{
		page.replace(at, marker.size(), token);
	}
	sendResponse(sock, 200, "OK", "text/html; charset=utf-8", page);
}

void HttpServer::sendApiMohStatus(int sock)
{
	RequestsHandler* handler = _handler.load(std::memory_order_acquire);
	if (handler == nullptr)
	{
		sendResponse(sock, 503, "Service Unavailable", "application/json",
		             "{\"error\":\"SIP engine not attached yet\"}");
		return;
	}

	// `supported` is the BUILD capability (is there a card at all), separate from
	// `loaded` (is a clip actually there) — the same distinction /api/status draws
	// for sd.present vs sd.mounted, and for the same reason: a client must be able
	// to tell "this board can't do MoH" from "nobody has uploaded a clip yet".
#if defined(PD_ETH_HAS_SD)
	const bool supported = true;
#else
	const bool supported = false;
#endif

	std::ostringstream json;
	json << "{\"supported\":" << (supported ? "true" : "false")
	     << ",\"loaded\":"    << (handler->holdMusicLoaded() ? "true" : "false")
	     << ",\"seconds\":"   << handler->holdMusicSeconds()
	     << ",\"listeners\":" << handler->holdMusicListeners()
	     << ",\"preview\":\"" << jsonEscape(handler->mohPreviewExtension()) << "\"}";
	sendResponse(sock, 200, "OK", "application/json", json.str());
}

void HttpServer::sendApiMohPreview(int sock, const std::string& body)
{
	RequestsHandler* handler = _handler.load(std::memory_order_acquire);
	if (handler == nullptr)
	{
		sendResponse(sock, 503, "Service Unavailable", "application/json",
		             "{\"error\":\"SIP engine not attached yet\"}");
		return;
	}

	const std::string ext = getFormParam(body, "extension");
	if (ext.empty())
	{
		sendResponse(sock, 400, "Bad Request", "application/json",
		             "{\"error\":\"extension is required\"}");
		return;
	}

	if (!handler->startMohPreview(ext))
	{
		// One 409 covering both causes, with a body that says which applies, rather
		// than making the operator guess: "nothing happened" is the least useful
		// possible answer when a phone did not ring.
		const bool loaded = handler->holdMusicLoaded();
		sendResponse(sock, 409, "Conflict", "application/json",
		             loaded
		               ? "{\"error\":\"extension is not registered\"}"
		               : "{\"error\":\"no hold clip loaded — upload one first\"}");
		return;
	}

	sendResponse(sock, 200, "OK", "application/json",
	             "{\"status\":\"ok\",\"message\":\"ringing " + jsonEscape(ext) + "\"}");
}

void HttpServer::sendApiMohPreviewStop(int sock)
{
	RequestsHandler* handler = _handler.load(std::memory_order_acquire);
	if (handler == nullptr)
	{
		sendResponse(sock, 503, "Service Unavailable", "application/json",
		             "{\"error\":\"SIP engine not attached yet\"}");
		return;
	}
	handler->stopMohPreview();   // idempotent: harmless when nothing is running
	sendResponse(sock, 200, "OK", "application/json", "{\"status\":\"ok\"}");
}

void HttpServer::handleMohUpload(int sock, const std::string& alreadyRead,
                                 size_t bodyStart, size_t contentLength)
{
	const char*  prefix    = (bodyStart <= alreadyRead.size())
	                             ? alreadyRead.data() + bodyStart : nullptr;
	const size_t prefixLen = (bodyStart <= alreadyRead.size())
	                             ? alreadyRead.size() - bodyStart : 0;

	// Bound the upload. The clip is read into PSRAM in full, so an unbounded one
	// would exhaust the heap and take the SIP engine down with it. 8 MB is ~17
	// minutes of mu-law, far past any sane hold loop, and still leaves PSRAM for
	// the anchor task stacks.
	static constexpr size_t kMaxClipBytes = 8u * 1024u * 1024u;
	if (contentLength > kMaxClipBytes)
	{
		streamBody(sock, prefix, prefixLen, contentLength,
		           [](const uint8_t*, size_t) { return true; });
		sendResponse(sock, 413, "Payload Too Large", "application/json",
		             "{\"error\":\"clip exceeds 8 MB\"}");
		return;
	}

#if defined(PD_ETH_HAS_SD)
	// Write to a TEMPORARY name and rename on success. A half-written moh.wav
	// would fail HoldMusic's format check on the next boot and silently drop every
	// parked caller back to silence; worse, a truncated-but-valid-looking file
	// would loop a fragment. The rename is the commit point.
	const char* kTmp   = "/sdcard/moh.part";
	const char* kFinal = "/sdcard/moh.wav";

	std::FILE* f = std::fopen(kTmp, "wb");
	if (f == nullptr)
	{
		streamBody(sock, prefix, prefixLen, contentLength,
		           [](const uint8_t*, size_t) { return true; });
		sendResponse(sock, 500, "Internal Server Error", "application/json",
		             "{\"error\":\"cannot open /sdcard for writing — card mounted?\"}");
		return;
	}

	bool writeOk = streamBody(sock, prefix, prefixLen, contentLength,
		[f](const uint8_t* p, size_t n) {
			return std::fwrite(p, 1, n, f) == n;
		});

	std::fclose(f);

	if (!writeOk)
	{
		std::remove(kTmp);
		sendResponse(sock, 400, "Bad Request", "application/json",
		             "{\"error\":\"incomplete upload or SD write failed\"}");
		return;
	}

	std::remove(kFinal);            // rename() will not overwrite on FatFs
	if (std::rename(kTmp, kFinal) != 0)
	{
		std::remove(kTmp);
		sendResponse(sock, 500, "Internal Server Error", "application/json",
		             "{\"error\":\"could not commit clip to /sdcard/moh.wav\"}");
		return;
	}

	// Load it now so the operator finds out immediately whether the file is
	// actually 8 kHz mono mu-law, rather than discovering silence the next time
	// somebody parks a call. A rejected clip leaves the previous one playing.
	RequestsHandler* handler = _handler.load(std::memory_order_acquire);
	if (handler == nullptr)
	{
		sendResponse(sock, 200, "OK", "application/json",
		             "{\"status\":\"ok\",\"message\":\"clip stored; will load on next boot\"}");
		return;
	}
	if (!handler->startHoldMusic(kFinal))
	{
		sendResponse(sock, 422, "Unprocessable Entity", "application/json",
		             "{\"error\":\"stored, but not 8 kHz mono mu-law WAV — "
		             "convert with: ffmpeg -i in.mp3 -ar 8000 -ac 1 -acodec pcm_mulaw moh.wav\"}");
		return;
	}

	std::ostringstream ok;
	ok << "{\"status\":\"ok\",\"seconds\":" << handler->holdMusicSeconds()
	   << ",\"bytes\":" << contentLength << "}";
	sendResponse(sock, 200, "OK", "application/json", ok.str());
#else
	// No card on this build. Drain the body so the client's send completes and it
	// gets a clean answer rather than a reset mid-upload.
	streamBody(sock, prefix, prefixLen, contentLength,
	           [](const uint8_t*, size_t) { return true; });
	sendResponse(sock, 501, "Not Implemented", "application/json",
	             "{\"error\":\"no SD card on this build — music on hold needs the "
	             "eth/elite board\"}");
#endif
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
	json << "\"running\":\""          << jsonEscape(OtaUpdater::runningPartitionLabel())    << "\",";
	json << "\"runningPartition\":\"" << jsonEscape(OtaUpdater::runningPartitionLabel())    << "\",";
	json << "\"inProgress\":"         << (OtaUpdater::isUpdateInProgress() ? "true" : "false") << ",";
	json << "\"boot\":\""             << jsonEscape(OtaUpdater::bootPartitionLabel())       << "\",";
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
