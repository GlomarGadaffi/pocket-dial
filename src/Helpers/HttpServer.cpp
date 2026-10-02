// HttpServer.cpp: Issues #23 and #28 resolved.
#include "HttpServer.hpp"
#include "RequestsHandler.hpp"
#if defined(POCKETDIAL_ANCHOR_BENCH_PROBE) && defined(ESP_PLATFORM)
#include "BenchProbe.hpp"        // #384 H1: /api/bench/fault (docs/BENCH_PROBE.md)
#endif
#include "DialPlan.hpp"          // Issue #69: dial-rule validation shared with setDialRule
#include "ServiceExtensions.hpp" // Issue #202: reserved engine-owned pseudo-AORs
#include "TelephonyApiConfig.hpp"
#include "DidMapping.hpp"
#include "CallDetailRecord.hpp"
#include "CdrArchive.hpp"  // Issue #194 Stage 1: SD CDR archive wipe on factory reset
#include "AdminAuth.hpp"
#include "CoreDumpStore.hpp"   // Issue #382: /api/coredump*
#include "FactoryReset.hpp"    // Issue #363: the secrets factory reset must erase
#include "DeviceConfig.hpp"
#include "ResetJournal.hpp"     // #473: report an incomplete factory reset on the next boot
#include "ResetGuard.hpp"      // #473: block NVS data writes while resetting
#include "FirmwareInfo.hpp"    // Issue #411: "version" / "firmware" in /api/status
#include <cstdio>   // std::snprintf: the factory-reset error body (#450)
#include "OtaUpdater.hpp"
#include "ProvisioningConfig.hpp"
#include "ArpLookup.hpp"
// Issue #328: DmaFramePool's counters are reported by /api/status. Included
// unconditionally, not in the ESP-only block below -- the pool has a real host
// implementation and is built into the host test target, so these numbers are
// live on both platforms and can be asserted by a host test rather than only
// eyeballed on hardware.
#include "DmaFramePool.hpp"
#include "RtpReceiver.hpp"     // Issue #469: rxOversizeDrops() on /api/status
#include "RtpSender.hpp"       // Issue #479: txPoolRefusals() on /api/status
#include "HoldMusic.hpp"       // Issue #466: clipRefusals() on /api/status
#include "PsramAllocator.hpp"  // Issue #466: psram::internalFallbacks() on /api/status
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
#include "TrunkConfigStore.hpp"
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
#include <cstdio>        // snprintf: sendStaticHtml's allocation-free head (#410)
#include <cstdlib>
#include <mutex>
#include <cstring>
#include <charconv>   // std::to_chars: /api/status numbers, no heap (#410)
#include <string_view>
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
// #450 (poll #455): the factory reset ends with a whole-NVS-partition erase.
#include "nvs_flash.h"
#include "esp_log.h"
// OTA reboot path needs esp_restart() + a deferred-restart FreeRTOS task. These
// are available on EVERY ESP transport (WiFi, Ethernet, display), not just
// POCKETDIAL_HAS_WIFI, so guard them on the platform rather than the transport.
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
// Issue #185: heap_caps_get_minimum_free_size(MALLOC_CAP_SPIRAM) for
// sendApiStatus's minFreeHeapSpiram field.
#include "esp_heap_caps.h"
// Issue #496 / #509 review: the IPv4 input guard's counts for /api/status.
#include "Ip4InputGuard.h"
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

	// #410: /api/status's output buffers, once, here -- never per request. A
	// failed allocation leaves that slot null; the route then answers 503.
	for (char*& b : _statusBuf)
	{
		b = static_cast<char*>(psram::allocPreferPsram(kStatusBufBytes));
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

	// Issue #540: port 0 asks the OS for a free port. Read back the one it
	// chose, so port() reports it -- host test suites no longer need fixed
	// ports and can run in parallel.
	if (_port == 0)
	{
		sockaddr_in bound{};
#if defined _WIN32 || defined _WIN64
		int boundLen = static_cast<int>(sizeof(bound));
#else
		socklen_t boundLen = sizeof(bound);
#endif
		if (getsockname(sock, reinterpret_cast<struct sockaddr*>(&bound), &boundLen) != 0)
		{
			closeSocket(sock);
			return false;
		}
		_port = ntohs(bound.sin_port);
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
	// Issue #540: every connection runs on a DETACHED thread whose lambda uses
	// `this` after handleClient() returns (recordConnStackHwm, releaseSource,
	// _activeConnections). Returning here while one is still running freed the
	// server under it -- a use-after-free that showed up as a segfault in a
	// later, unrelated test. No new connection can start (the accept thread is
	// joined), and each handler is bounded by the read deadline plus its own
	// work, so wait them out; the bound only guards against a wedged handler.
	const auto giveUp = std::chrono::steady_clock::now() +
		std::chrono::milliseconds(_readDeadlineMs + 5000);
	while (_activeConnections.load(std::memory_order_acquire) > 0 &&
		std::chrono::steady_clock::now() < giveUp)
	{
		std::this_thread::sleep_for(std::chrono::milliseconds(5));
	}
	// #540 review: giving up with a handler still running IS the use-after-free
	// above, just deferred. Never let it pass silently: say so, and on the host
	// (tests) stop right here, where the cause is, not in whatever runs next.
	const int stillRunning = _activeConnections.load(std::memory_order_acquire);
	if (stillRunning > 0)
	{
		std::cerr << "[HttpServer] destroyed with " << stillRunning
			<< " connection handler(s) still running after the read deadline + 5 s"
			   " -- a wedged handler will touch freed memory (#540)\n";
#if !defined(ESP_PLATFORM) && !defined(ESP32) && !defined(ARDUINO)
		std::abort();
#endif
	}
	// #410: a still-running handler may be reading its status buffer; leak them then.
	for (char* b : _statusBuf)
	{
		if (b != nullptr && stillRunning == 0) psram::freePreferPsram(b);
	}
}

void HttpServer::start()
{
	_running = true;
	_acceptThread = std::thread(&HttpServer::acceptLoop, this);
}

#if !defined(ESP_PLATFORM) && !defined(ESP32) && !defined(ARDUINO)
// #616: per option, so a test failing only the refusal's SO_SNDTIMEO does not
// also kill the slot holders' SO_RCVTIMEO (set again on every body-loop recv).
static std::atomic<bool> s_failRecvTimeoutForTest{false};
static std::atomic<bool> s_failSendTimeoutForTest{false};
void HttpServer::setFailSocketTimeoutsForTest(bool failRecv, bool failSend)
{
	s_failRecvTimeoutForTest.store(failRecv);
	s_failSendTimeoutForTest.store(failSend);
}
static void (*s_dispatchMarkForTest)() = nullptr;   // #410 route gate
void HttpServer::setDispatchMarkForTest(void (*mark)()) { s_dispatchMarkForTest = mark; }
#endif

// Issue #529: SO_RCVTIMEO / SO_SNDTIMEO in milliseconds (at least 1, so 0 never
// means "forever"). Returns false if the option did not take (#534 review):
// the caller must then not block on the socket at all, because an unbounded
// recv() or send() is exactly the slot-holding hang the timeout is there for.
static bool setSocketTimeoutMs(int sock, int opt, long ms)
{
#if !defined(ESP_PLATFORM) && !defined(ESP32) && !defined(ARDUINO)
	if ((opt == SO_RCVTIMEO && s_failRecvTimeoutForTest.load()) ||
		(opt == SO_SNDTIMEO && s_failSendTimeoutForTest.load())) return false;
#endif
	if (ms < 1) ms = 1;
#if defined _WIN32 || defined _WIN64
	DWORD tv = static_cast<DWORD>(ms);
	return setsockopt(sock, SOL_SOCKET, opt, reinterpret_cast<const char*>(&tv), sizeof(tv)) == 0;
#else
	struct timeval tv{};
	tv.tv_sec  = ms / 1000;
	tv.tv_usec = (ms % 1000) * 1000;
	return setsockopt(sock, SOL_SOCKET, opt, &tv, sizeof(tv)) == 0;
#endif
}

static bool setRecvTimeoutMs(int sock, long ms) { return setSocketTimeoutMs(sock, SO_RCVTIMEO, ms); }

void HttpServer::acceptLoop()
{
	// The accept thread's refusals (#368 global cap, #529 per-source) must never
	// block it: bound the send, and if even that cannot be set, close unanswered
	// (#534 review). A dropped connection costs the refused client a retry; a
	// send() that blocks forever costs every client the whole server.
	const auto refuseBusy = [this](int sock, const char* body) {
		if (setSocketTimeoutMs(sock, SO_SNDTIMEO, 1000))
		{
			sendResponse(sock, 503, "Service Unavailable", "application/json", body);
		}
		closeSocket(sock);
	};

	// Issue #382: checksum + summarise any stored coredump ONCE, here -- this
	// thread runs on the 8192-byte pthread default (it never resizes itself,
	// see below), unlike the 4 KB per-connection threads /api/coredump/info is
	// served on (#405 measured those down to 472 bytes free). start() itself
	// is the wrong place: the display build calls it from app_main's 3.5 KB
	// stack. Costs the first accept one checksum walk over at most 128 KB.
	// It also caches the presence probe itself (#405): after this, /api/status
	// and the coredump routes never touch the partition per request.
	CoreDumpStore::prime();
	// #481 review: load the reset journal's boot status here too, before the
	// first accept -- the flash read and the one-time lock setup happen on this
	// 8 KB thread once, never on a 4 KB http_conn thread per request.
	(void)resetjournal::bootStatus();

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
		// Issue #368: bound how many handler threads can exist at once. Each one
		// costs a task stack + TCB + socket buffers out of INTERNAL DRAM, and that
		// is the same pool the W5500 driver takes its DMA bounce buffer from -- so
		// an unbounded count does not just refuse dashboard requests, it stops the
		// device transmitting Ethernet frames. Measured on .244: 8 concurrent
		// requests took minFreeHeapInternal to 7412 bytes, 12 produced
		// "spicommon_dma_setup_priv_buffer: Failed to allocate priv TX buffer" and
		// dropped frames, 16 took it to 624 bytes. /api/status is deliberately
		// unauthenticated (#207) so the burst needs no credentials.
		//
		// Refusing early and cheaply is strictly better than letting the spawn fail
		// deeper in: the caller gets a 503 it can retry instead of a dropped socket,
		// and the memory is never committed in the first place.
		if (_activeConnections.load(std::memory_order_acquire) >= kMaxConcurrentConnections)
		{
			// This refusal is written from the ACCEPT THREAD, not a handler, so it
			// must not be allowed to block: a client that completes the handshake
			// and then never reads would otherwise wedge the accept loop on send()
			// and take the whole server down -- a far worse denial of service than
			// the exhaustion this cap exists to prevent. handleClient()'s 5 s
			// SO_RCVTIMEO (#23) is set on the handler path we are deliberately
			// skipping here, so this socket needs its own bound (refuseBusy).
			refuseBusy(clientSock, "{\"error\":\"busy\",\"message\":\"too many concurrent connections\"}");
			continue;
		}

		// Issue #529: one source may not hold every slot. Refused the same
		// non-blocking way as the global cap above, and counted.
		const uint32_t sourceAddr = clientAddr.sin_addr.s_addr;
		if (!claimSource(sourceAddr))
		{
			_perSourceRefusals.fetch_add(1, std::memory_order_relaxed);
			refuseBusy(clientSock, "{\"error\":\"busy\",\"message\":\"too many connections from this address\"}");
			continue;
		}

		// Claimed BEFORE the thread exists so a burst arriving faster than the
		// threads can start cannot overshoot the cap; the thread body releases it
		// on every exit path, and the catch below releases it if no thread was
		// ever created.
		_activeConnections.fetch_add(1, std::memory_order_acq_rel);

		try
		{
			std::thread([this, clientSock, sourceAddr]() {
				// #405: which route this thread served, for the stack minimum.
				char route[kRouteLabelBytes] = "unparsed";
				handleClient(clientSock, route);
				recordConnStackHwm(route);
				releaseSource(sourceAddr);
				_activeConnections.fetch_sub(1, std::memory_order_acq_rel);
			}).detach();
		}
		catch (const std::exception& e)
		{
			// No thread was created, so nothing will ever decrement for this one.
			releaseSource(sourceAddr);
			_activeConnections.fetch_sub(1, std::memory_order_acq_rel);
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

bool HttpServer::claimSource(uint32_t addr)
{
	std::lock_guard<std::mutex> lock(_sourcesMutex);
	SourceSlot* freeSlot = nullptr;
	for (SourceSlot& s : _sources)
	{
		if (s.count > 0 && s.addr == addr)
		{
			if (s.count >= kMaxConnectionsPerSource) return false;
			++s.count;
			return true;
		}
		if (s.count == 0 && freeSlot == nullptr) freeSlot = &s;
	}
	// The global cap is checked first, so a live source always has a slot here;
	// refuse rather than overrun if that ever stops being true.
	if (freeSlot == nullptr) return false;
	freeSlot->addr = addr;
	freeSlot->count = 1;
	return true;
}

void HttpServer::releaseSource(uint32_t addr)
{
	std::lock_guard<std::mutex> lock(_sourcesMutex);
	for (SourceSlot& s : _sources)
	{
		if (s.count > 0 && s.addr == addr)
		{
			--s.count;
			return;
		}
	}
}


void HttpServer::routeLabel(const std::string& method, const std::string& path,
                            char* out, size_t cap)
{
	if (out == nullptr || cap == 0) return;
	size_t n = 0;
	const auto put = [&](std::string_view v) {
		for (char c : v)
		{
			if (n + 1 >= cap) return;
			out[n++] = c;
		}
	};

	bool methodOk = !method.empty() && method.size() <= 7;
	for (char c : method) methodOk = methodOk && c >= 'A' && c <= 'Z';
	put(methodOk ? std::string_view(method) : std::string_view("?"));
	put(" ");

	if (path == "/" || path == "/index.html") put("/");
	else if (path == "/metrics") put("/metrics");
	else if (isProvisioningConfigPath(path)) put("provisioning");
	else
	{
		// Under /api/ and /setup/ keep lower-case word segments; the first numeric
		// or unknown one ends the label, so a slot index or an extension never
		// appears. Anything else (a 404 probe, a scan) is just "other".
		const std::string_view p(path);
		const bool known = p.substr(0, 5) == "/api/" || p.substr(0, 7) == "/setup/";
		size_t kept = 0;
		size_t pos = 0;
		while (known && pos < p.size() && p[pos] == '/')
		{
			size_t end = p.find('/', pos + 1);
			if (end == std::string_view::npos) end = p.size();
			const std::string_view seg = p.substr(pos + 1, end - pos - 1);
			bool word = !seg.empty() && seg.size() <= 24;
			bool digits = word;
			for (char c : seg)
			{
				const bool d = c >= '0' && c <= '9';
				word = word && (d || (c >= 'a' && c <= 'z') || c == '-' || c == '_');
				digits = digits && d;
			}
			if (!word || digits) break;
			put("/");
			put(seg);
			++kept;
			pos = end;
		}
		if (kept == 0) put("other");
	}
	out[n] = '\0';
}

void HttpServer::handleClient(int clientSock, char* routeOut)
{
	// Issue #529: everything read before dispatch shares one deadline.
	const auto readDeadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(_readDeadlineMs);
	const auto msLeft = [&readDeadline]() -> long {
		return static_cast<long>(std::chrono::duration_cast<std::chrono::milliseconds>(
			readDeadline - std::chrono::steady_clock::now()).count());
	};

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
	// Issue #529: 5 s per recv(), but never past the read deadline. If the
	// timeout cannot be set, recv() would wait forever: drop the connection
	// unread and count it with the deadline drops (#534 review).
	if (!setRecvTimeoutMs(clientSock, (std::min)(5000L, _readDeadlineMs)))
	{
		_readDeadlineDrops.fetch_add(1, std::memory_order_relaxed);
		closeSocket(clientSock);
		return;
	}

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
				if (routeOut) routeLabel(otaReq.method, otaReq.path, routeOut, kRouteLabelBytes);

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
					// Issue #529: a body trickled in a byte every few seconds used to
					// hold this slot for as long as the sender liked, before any auth
					// check. Each wait is now cut to what is left of the deadline,
					// and a body not in by then is dropped and counted.
					const long left = msLeft();
					if (left <= 0)
					{
						_readDeadlineDrops.fetch_add(1, std::memory_order_relaxed);
						closeSocket(clientSock);
						return;
					}
					if (!setRecvTimeoutMs(clientSock, (std::min)(5000L, left)))
					{
						_readDeadlineDrops.fetch_add(1, std::memory_order_relaxed);
						closeSocket(clientSock);
						return;
					}
					buf.assign(buf.size(), 0);
#if defined _WIN32 || defined _WIN64
					int n = recv(clientSock, buf.data(), static_cast<int>(buf.size()) - 1, 0);
#else
					int n = static_cast<int>(recv(clientSock, buf.data(), buf.size() - 1, 0));
#endif
					if (n <= 0 && msLeft() <= 0)
					{
						_readDeadlineDrops.fetch_add(1, std::memory_order_relaxed);
						closeSocket(clientSock);
						return;
					}
					if (n <= 0) break;
					raw.append(buf.data(), static_cast<size_t>(n));
					bodyHave += static_cast<size_t>(n);
				}
			}
		}
	}

	HttpRequest req = parseRequest(raw);
	// Issue #528: the peer address captured above, on EVERY request -- only the
	// OTA/MoH streaming branch used to set it. Without it the login lockout keyed
	// every client to the same "" bucket, so one host guessing passwords locked
	// the real admin out too, and Cisco SPA model-keyed provisioning never ran
	// its ARP lookup.
	req.clientIp = peerIp;
	if (routeOut) routeLabel(req.method, req.path, routeOut, kRouteLabelBytes);   // #405
	// Out-param for the two telephony-config routes below, whose slot index is
	// a URL path segment rather than a form param (see parseTelephonyConfigSlotPath).
	size_t telSlotIdx = 0;
#if !defined(ESP_PLATFORM) && !defined(ESP32) && !defined(ARDUINO)
	if (s_dispatchMarkForTest) s_dispatchMarkForTest();   // #410: route allocations start here
#endif

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
	else if (req.method == "GET" && req.path == "/setup/trunk")
	{
		// Ungated shell, same class as "/" and /setup/email -- the page itself
		// holds no data; every value on it arrives via the gated /api/trunk.
		sendTrunkSetupHtml(clientSock, req);
	}
	else if (req.method == "GET" && req.path == "/api/trunk")
	{
		// Gated: discloses the carrier, the proxy and the auth ID -- exactly the
		// infrastructure detail /api/email and /api/syslog are gated for. The
		// password is never in this body at all (hasPassword only).
		if (requireAdmin(clientSock, req, false))
		{
			sendApiTrunkConfig(clientSock);
		}
	}
	else if (req.method == "POST" && req.path == "/api/trunk")
	{
		if (requireAdmin(clientSock, req, true))
		{
			sendApiTrunkConfigSet(clientSock, req.body);
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
	else if (req.method == "GET" && req.path == "/api/coredump/info")
	{
		// Issue #382: which task panicked, at what PC, from which ELF. Gated like
		// /api/pcap -- a PC and task name are diagnostic detail, not login-form
		// material (THREAT_MODEL.md section 4 E-2).
		if (requireAdmin(clientSock, req, false))
		{
			sendApiCoreDumpInfo(clientSock);
		}
	}
	else if (req.method == "GET" && req.path == "/api/coredump")
	{
		// Issue #382: the raw dump. Owner-gated, the same tier as config export
		// WITH secrets (#173): a coredump is a copy of task stacks at the moment
		// of the panic, and a stack can hold a digest secret, an OAuth token or a
		// TLS session key as easily as a return address. Like every #173 owner
		// action, a sysop passes while NO owner account exists yet
		// (AdminAuth::sessionSatisfiesRole's no-owner fallback).
		if (requireAdmin(clientSock, req, false, AdminAuth::Role::Owner))
		{
			sendApiCoreDump(clientSock);
		}
	}
	else if (req.method == "POST" && req.path == "/api/coredump/erase")
	{
		// Mutating (destroys evidence), so CSRF-checked like every other POST.
		if (requireAdmin(clientSock, req, true))
		{
			sendApiCoreDumpErase(clientSock);
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
		// Plaintext-only export. Read, but genuinely sensitive (which extensions
		// are secured, the dial plan, MAC bindings -- never a digest HA1, #482) --
		// sysop-gated, not public like /api/status.
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
			// #484 review finding 4: the encrypted block now holds a
			// password-equivalent for every secured extension, and PBKDF2 buys
			// little against an offline guess of a short password.
			static constexpr size_t kMinExportPasswordLen = 12;
			if (withSecrets && password.size() < kMinExportPasswordLen)
			{
				sendResponse(clientSock, 400, "Bad Request", "application/json",
				             "{\"error\":\"the export password must be at least 12 characters\"}");
			}
			else
			{
				sendApiConfigExport(clientSock, withSecrets, password);
			}
		}
	}
	else if (req.method == "POST" && req.path == "/api/config/import")
	{
		// A plaintext-only restore is sysop-level: restoring config is not one of
		// #173's owner-only actions, and it has its own confirm-before-overwrite
		// interlock (checked inside the handler). But a non-empty `password`
		// means the encrypted secretsEnc block will be applied -- digest HA1s,
		// the Wi-Fi password, the AP PSK -- and that is exactly what
		// export-with-secrets reads, so it takes the SAME owner gate. The
		// block authenticates the password, not who made the file: without this,
		// a sysop could seal their own HA1 for any extension offline and take it
		// over (#484 review, Crew finding 1).
		const bool withSecrets = !getFormParam(req.body, "password").empty();
		if (requireAdmin(clientSock, req, true,
			withSecrets ? AdminAuth::Role::Owner : AdminAuth::Role::Sysop))
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
	else if (req.method == "GET" && req.path == "/api/pnp")
	{
		if (requireAdmin(clientSock, req, false))
		{
			sendApiPnp(clientSock);
		}
	}
	else if (req.method == "POST" && req.path == "/api/pnp")
	{
		if (requireAdmin(clientSock, req, true))
		{
			sendApiPnpSet(clientSock, req.body);
		}
	}
	else if (req.method == "GET" && req.path == "/api/zero-touch")
	{
		if (requireAdmin(clientSock, req, false))
		{
			sendApiZeroTouch(clientSock);
		}
	}
	else if (req.method == "POST" && req.path == "/api/zero-touch")
	{
		if (requireAdmin(clientSock, req, true))
		{
			sendApiZeroTouchSet(clientSock, req.body);
		}
	}
	else if (req.method == "POST" && req.path == "/api/registrar/forget-learned")
	{
		// #515: one action to clear a flood of Learned adoptions; Secured
		// devices stay. Answers with the same device list as GET /api/registrar.
		if (requireAdmin(clientSock, req, true))
		{
			RequestsHandler* handler = _handler.load(std::memory_order_acquire);
			if (handler) handler->forgetLearnedDevices();
			sendApiRegistrar(clientSock);
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
			sendApiOtaReboot(clientSock, req.body);
		}
	}
#if defined(POCKETDIAL_ANCHOR_BENCH_PROBE) && defined(ESP_PLATFORM)
	else if ((req.method == "GET" || req.method == "POST") && req.path == "/api/bench/fault")
	{
		// #384 H1: the bench probe image only (docs/BENCH_PROBE.md). Owner-gated like
		// /api/coredump; a POST changes call behaviour, so it is CSRF-checked too.
		if (requireAdmin(clientSock, req, req.method == "POST", AdminAuth::Role::Owner))
		{
			sendApiBenchFault(clientSock, req);
		}
	}
#endif
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

// --- Security headers, emitted centrally so no endpoint can forget them ---
// One constant, written verbatim by sendResponseWithHeader(), by
// buildResponseHead() and by the streamed static pages (sendStaticHtml, #410),
// so no two paths can drift.
//
// The dashboard is a single self-contained page with inline <script>/<style>
// and no external origins, so the policy can be this tight: nothing loads
// from anywhere, the page cannot be framed, and XHR/fetch is same-origin.
// Cache-Control: responses carry call metadata, the CSRF token and (on
// /api/pcap) raw SIP bytes; none of it should sit in a shared browser cache or
// on disk. Referrer-Policy is same-origin, not no-referrer: the Referer header
// stays available as a same-origin signal, and nothing here is linked
// off-device anyway. Deliberately NO Strict-Transport-Security: the dashboard
// is plain HTTP on a LAN appliance; pinning HSTS here would make the host
// unreachable over http:// forever with no way for a user to override it.
static constexpr char kSecurityHeaders[] =
	"Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; "
	"style-src 'unsafe-inline'; img-src data:; connect-src 'self'; "
	"form-action 'self'; frame-ancestors 'none'; base-uri 'none'\r\n"
	"X-Frame-Options: DENY\r\n"
	"X-Content-Type-Options: nosniff\r\n"
	"Cache-Control: no-store\r\n"
	"Referrer-Policy: same-origin\r\n";

size_t HttpServer::headPieces(SendPiece* v, HeadNumbers& nums, int statusCode,
                              std::string_view statusText, std::string_view contentType,
                              size_t contentLength, std::string_view extraHeader)
{
	// Only the two numbers are formatted; every other range is sent from where
	// it already lives. Byte-identical to the pre-#410 ostringstream head
	// (HttpSendPath_test compares against buildResponseHead() itself).
	// No Access-Control-Allow-Origin header: wildcard CORS would allow any
	// browser tab on the same AP to fire side-effecting POSTs without a preflight.
	const int ns = std::snprintf(nums.status, sizeof(nums.status), "HTTP/1.1 %d ", statusCode);
	const int nl = std::snprintf(nums.length, sizeof(nums.length), "\r\nContent-Length: %zu\r\n", contentLength);
	if (ns <= 0 || static_cast<size_t>(ns) >= sizeof(nums.status) ||
	    nl <= 0 || static_cast<size_t>(nl) >= sizeof(nums.length))
		return 0;   // cannot happen for an int and a size_t; never send a torn head
	static constexpr char kTypeKey[] = "\r\nContent-Type: ";
	static constexpr char kCrlf[] = "\r\n";
	static constexpr char kTail[] = "Connection: close\r\n\r\n";
	size_t n = 0;
	const auto add = [&](const char* p, size_t len) {
		if (len == 0) return;   // sendAllPieces() never sees an empty range
		if (n >= kHeadPieces) { n = kHeadPieces + 1; return; }   // cannot happen (9 add() calls); poisons the result below
		v[n].iov_base = const_cast<char*>(p);
		v[n].iov_len = len;
		++n;
	};
	add(nums.status, static_cast<size_t>(ns));
	add(statusText.data(), statusText.size());
	add(kTypeKey, sizeof(kTypeKey) - 1);
	add(contentType.data(), contentType.size());
	add(nums.length, static_cast<size_t>(nl));
	add(kSecurityHeaders, sizeof(kSecurityHeaders) - 1);
	if (!extraHeader.empty())
	{
		add(extraHeader.data(), extraHeader.size());
		add(kCrlf, sizeof(kCrlf) - 1);
	}
	add(kTail, sizeof(kTail) - 1);
	return n <= kHeadPieces ? n : 0;   // never overrun a caller's v[kHeadPieces (+1)]
}

void HttpServer::sendResponseWithHeader(int sock, int statusCode, std::string_view statusText,
                              std::string_view contentType, std::string_view body,
                              std::string_view extraHeader)
{
	// #410 phase 2: every route's response goes out IN PLACE. This used to
	// build the head in an ostringstream, copy it and the whole body into a
	// second one, then copy that again with str() -- two full body copies plus
	// the head per response, all from internal DRAM for anything under the
	// 16 KB SPIRAM_MALLOC_ALWAYSINTERNAL line (#328), i.e. nearly every JSON
	// body, /api/status polling included. Now the head is headPieces()'s
	// ranges and the body is one more, all in one scatter-gather write. The
	// frame is kept small on purpose -- this runs on the 4 KB http_conn stack
	// for every route (#405): the ranges are built once, as the iovec array
	// sendmsg() takes, and trimmed in place on a short write.
	//
	// (CodeQL flagged a `head += body` shape here as "cleartext transmission"
	// of emailConfigJson() on PR #394 -- a false positive: its secrets leave
	// only as hasPassword/hasGsaKey booleans, #207.)
	HeadNumbers nums;
	SendPiece v[kHeadPieces + 1];
	size_t n = headPieces(v, nums, statusCode, statusText, contentType, body.size(), extraHeader);
	if (n == 0) return;
	if (!body.empty())
	{
		v[n].iov_base = const_cast<char*>(body.data());
		v[n].iov_len = body.size();
		++n;
	}
	sendAllPieces(sock, v, n);
}

size_t HttpServer::consumeSent(SendPiece* v, size_t first, size_t n, size_t sent)
{
	// Whole ranges first, then into a partial one.
	while (first < n && sent >= v[first].iov_len)
	{
		sent -= v[first].iov_len;
		++first;
	}
	if (first < n && sent > 0)
	{
		v[first].iov_base = static_cast<char*>(v[first].iov_base) + sent;
		v[first].iov_len -= sent;
	}
	return first;
}

bool HttpServer::sendAllPieces(int sock, SendPiece* v, size_t n)
{
	size_t first = 0;
	while (first < n)
	{
#if defined _WIN32 || defined _WIN64
		// No sendmsg() on Winsock; host-only, so one range per send() will do.
		const int sent = ::send(sock, static_cast<const char*>(v[first].iov_base),
		                        static_cast<int>(v[first].iov_len), 0);
#else
		struct msghdr msg;
		std::memset(&msg, 0, sizeof(msg));   // msg_name must be null for TCP (lwIP checks)
		msg.msg_iov = v + first;
		msg.msg_iovlen = static_cast<decltype(msg.msg_iovlen)>(n - first);
		const ssize_t sent = ::sendmsg(sock, &msg, 0);
#endif
		if (sent <= 0) return false;
		first = consumeSent(v, first, n, static_cast<size_t>(sent));
	}
	return true;
}

bool HttpServer::sendAllBytes(int sock, const char* ptr, size_t remaining)
{
	while (remaining > 0)
	{
#if defined _WIN32 || defined _WIN64
		int sent = ::send(sock, ptr, static_cast<int>(remaining), 0);
#else
		int sent = static_cast<int>(::send(sock, ptr, remaining, 0));
#endif
		if (sent <= 0) return false;
		ptr += sent;
		remaining -= static_cast<size_t>(sent);
	}
	return true;
}

#if !defined(ESP_PLATFORM) && !defined(ESP32) && !defined(ARDUINO)
// The pre-#410 head, kept verbatim as the tests' reference: status line +
// every header + the blank line, for a body of contentLength bytes.
std::string HttpServer::buildResponseHead(int statusCode, const std::string& statusText,
                              const std::string& contentType, size_t contentLength,
                              const std::string& extraHeader)
{
	std::ostringstream resp;
	resp << "HTTP/1.1 " << statusCode << " " << statusText << "\r\n";
	resp << "Content-Type: " << contentType << "\r\n";
	resp << "Content-Length: " << contentLength << "\r\n";
	resp << kSecurityHeaders;
	if (!extraHeader.empty())
	{
		resp << extraHeader << "\r\n";
	}
	resp << "Connection: close\r\n";
	resp << "\r\n";
	return resp.str();
}
#endif

void HttpServer::sendResponse(int sock, int statusCode, std::string_view statusText,
                              std::string_view contentType, std::string_view body)
{
	sendResponseWithHeader(sock, statusCode, statusText, contentType, body, "");
}

// The placeholder every static page carries where the session's CSRF token goes.
static constexpr char kCsrfMarker[] = "__PD_CSRF__";

void HttpServer::sendStaticHtml(int sock, const char* const* parts, const size_t* sizes,
                                size_t count, const std::string& token)
{
	// Where is the marker? Scanned per call over the flash-resident parts with
	// string_view (no allocation), never cached: a page edit that moves the
	// marker to another part must not silently ship a literal "__PD_CSRF__" and
	// no token -- every form POST would then fail CSRF with no diagnostic. Only
	// the FIRST occurrence is replaced, exactly as the old find()/replace() did;
	// HttpStaticPages_test pins that every page carries exactly one. A marker
	// MUST NOT straddle two parts -- a re-split of index_html.h may fall at any
	// byte, and a straddled marker would be sent literally. That is not
	// structural: EveryPageCarriesExactlyOneCsrfMarker enforces it.
	const std::string_view marker(kCsrfMarker, sizeof(kCsrfMarker) - 1);
	size_t markPart = count, markAt = 0, total = 0;
	for (size_t i = 0; i < count; ++i)
	{
		total += sizes[i];
		if (markPart == count)
		{
			const size_t at = std::string_view(parts[i], sizes[i]).find(marker);
			if (at != std::string_view::npos) { markPart = i; markAt = at; }
		}
	}
	const size_t contentLength = (markPart == count)
		? total : total - marker.size() + token.size();

	// The head: the same builder every response uses (headPieces), in one write.
	{
		HeadNumbers nums;
		SendPiece v[kHeadPieces];
		const size_t n = headPieces(v, nums, 200, "OK", "text/html; charset=utf-8", contentLength, "");
		if (n == 0 || !sendAllPieces(sock, v, n)) return;
	}

	// The body, straight from flash. Only the marker's part is split.
	for (size_t i = 0; i < count; ++i)
	{
		if (i != markPart)
		{
			if (!sendAllBytes(sock, parts[i], sizes[i])) return;
			continue;
		}
		if (!sendAllBytes(sock, parts[i], markAt)) return;
		if (!sendAllBytes(sock, token.data(), token.size())) return;
		const size_t after = markAt + marker.size();
		if (!sendAllBytes(sock, parts[i] + after, sizes[i] - after)) return;
	}
}

void HttpServer::sendHtml(int sock, const HttpRequest& req)
{
	// index_html.h stores the page as independent const char[] parts (each
	// its own flash-resident literal, never concatenated at compile time --
	// see that header's comment for why) rather than one combined constant.
	// Since #410 they are never assembled at all: sendStaticHtml() writes each
	// part to the socket in place. Assembling them used to cost ~116 KB per load,
	// three times over (the page, then sendResponse's two body copies).
	const char* parts[CGA_INDEX_HTML_PART_COUNT];
	size_t sizes[CGA_INDEX_HTML_PART_COUNT];
	for (size_t i = 0; i < CGA_INDEX_HTML_PART_COUNT; ++i)
	{
		parts[i] = CGA_INDEX_HTML_PARTS[i].data;
		sizes[i] = CGA_INDEX_HTML_PARTS[i].size;
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
	sendStaticHtml(sock, parts, sizes, CGA_INDEX_HTML_PART_COUNT, token);
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

// #410: bounded JSON writer over a caller-owned fixed buffer -- no heap. Once
// an append does not fit, `full` latches and every later append is a no-op;
// the caller refuses the response rather than send a truncated body.
namespace
{
	struct JsonOut
	{
		char* buf = nullptr;
		size_t cap = 0;
		size_t len = 0;
		bool full = false;

		JsonOut& s(std::string_view v)
		{
			if (full || v.size() > cap - len) { full = true; return *this; }
			std::memcpy(buf + len, v.data(), v.size());
			len += v.size();
			return *this;
		}
		JsonOut& b(bool v) { return s(v ? "true" : "false"); }
		template <class T> JsonOut& n(T v)
		{
			char t[24];
			const auto r = std::to_chars(t, t + sizeof(t), v);
			if (r.ec != std::errc{}) { full = true; return *this; }
			return s(std::string_view(t, static_cast<size_t>(r.ptr - t)));
		}
		// Same escaping as jsonEscape(), written in place.
		JsonOut& e(std::string_view v)
		{
			static const char* hex = "0123456789abcdef";
			for (unsigned char c : v)
			{
				switch (c)
				{
					case '"':  s("\\\""); break;
					case '\\': s("\\\\"); break;
					case '\n': s("\\n");  break;
					case '\r': s("\\r");  break;
					case '\t': s("\\t");  break;
					default:
						if (c < 0x20)
						{
							const char u[6] = { '\\', 'u', '0', '0', hex[(c >> 4) & 0x0F], hex[c & 0x0F] };
							s(std::string_view(u, 6));
						}
						else
						{
							const char ch = static_cast<char>(c);
							s(std::string_view(&ch, 1));
						}
				}
			}
			return *this;
		}
	};
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
static void pdAppendHwmField(JsonOut& json, const char* key, long bytes)
{
	json.s(",\"").s(key).s("\":");
	if (bytes < 0) json.s("null"); else json.n(bytes);
}
#endif // ESP_PLATFORM

void HttpServer::recordConnStackHwm(const char* route)
{
#if !defined(ESP_PLATFORM)
	(void)route;
#else
	// uxTaskGetStackHighWaterMark returns the smallest amount of free stack this
	// task has ever had, in WORDS on Xtensa -- multiply for the bytes every other
	// stackHwm_* field reports. Called on the connection thread itself, right
	// after the request has been served, so it covers whatever depth that
	// particular route reached.
	const long freeBytes =
		static_cast<long>(uxTaskGetStackHighWaterMark(nullptr)) * sizeof(StackType_t);

	// Keep the WORST (smallest-free) figure any connection has produced since
	// boot, with the route that produced it (#405). Under a mutex rather than a
	// compare-exchange loop: several connection threads can finish at once, the
	// deepest one must win, and its route has to land with its figure. The
	// figure stays atomic so /api/status's stackHwm_http_conn read is unchanged.
	std::lock_guard<std::mutex> lk(_httpConnWorstMutex);
	const long prev = _httpConnStackHwmBytes.load(std::memory_order_relaxed);
	if (prev < 0 || freeBytes < prev)
	{
		_httpConnStackHwmBytes.store(freeBytes, std::memory_order_relaxed);
		std::snprintf(_httpConnWorstRoute, sizeof(_httpConnWorstRoute), "%s",
		              route != nullptr ? route : "");
	}
#endif
}

char* HttpServer::leaseStatusBuf(std::atomic<bool>*& busy)
{
	for (int i = 0; i < kStatusBufCount; ++i)
	{
		if (_statusBuf[i] != nullptr && !_statusBufBusy[i].exchange(true, std::memory_order_acquire))
		{
			busy = &_statusBufBusy[i];
			return _statusBuf[i];
		}
	}
	return nullptr;
}

void HttpServer::sendApiStatus(int sock, bool authenticated)
{
	// #410: polled every second by the dashboard, so no heap per request. The
	// body is written into this connection's fixed buffer (allocated in the
	// constructor) and sent from there; the snapshot tables are formatted in
	// place under the snapshot lock instead of copied out. A body that does not
	// fit is refused with a 500 and counted -- never truncated, never grown.
	std::atomic<bool>* busy = nullptr;
	char* buf = leaseStatusBuf(busy);
	if (buf == nullptr)   // all busy (fewer buffers than slots without PSRAM), or failed at boot
	{
		_statusRefusals.fetch_add(1, std::memory_order_relaxed);
		sendResponse(sock, 503, "Service Unavailable", "application/json",
			"{\"error\":\"no status buffer\"}");
		return;
	}
	struct Release
	{
		std::atomic<bool>* f;
		~Release() { f->store(false, std::memory_order_release); }
	} release{busy};   // held until the send below has finished reading buf
	JsonOut json{buf, (std::min)(_statusCap, kStatusBufBytes)};

	uint64_t uptimeMs = currentTimeMs() - _startTime;
	uint64_t uptimeSec = uptimeMs / 1000;

	uint64_t packets = 0;
	uint64_t dropped = 0;
	bool e911Configured = false;
	uint64_t droppedInvalid = 0;   // Issue #430
	uint64_t droppedRate = 0;
	uint64_t keepalivesCrlf = 0;   // Issue #430: not drops
	const char* emergencyRoute = nullptr;   // Issue #521; omitted with no engine
	uint64_t droppedNoPool = 0;    // Issue #443/#444: discarded before handle()
	uint64_t droppedOversize = 0;
	uint64_t recvErrors = 0;
	int lastRecvErrno = 0;

	RequestsHandler* handler = _handler.load(std::memory_order_acquire);
	if (handler != nullptr)
	{
		packets = handler->getPacketsProcessed();
		dropped = handler->getPacketsDropped();   // Issue #38
		e911Configured = handler->isE911Configured();   // #450
		droppedInvalid = handler->getDroppedInvalid();
		droppedRate = handler->getDroppedRate();
		keepalivesCrlf = handler->getKeepalivesCrlf();
		emergencyRoute = RequestsHandler::emergencyRouteName(handler->emergencyRoute());
		const DropProbe& probe = handler->getDropProbe();
		droppedNoPool = probe.count(DropProbe::Reason::NoPool);
		droppedOversize = probe.count(DropProbe::Reason::Oversize);
		recvErrors = probe.recvErrorCount();
		lastRecvErrno = probe.lastRecvErrno();
	}

	char displayIp[INET_ADDRSTRLEN] = "";
	if (_ip == "0.0.0.0")
	{
		// false leaves "127.0.0.1" in displayIp, the same fallback getPrimaryLocalIP() gives.
		(void)getPrimaryLocalIPInto(displayIp, sizeof(displayIp));
	}

	json.s("{");
	json.s("\"ip\":\"").e(displayIp[0] ? std::string_view(displayIp) : std::string_view(_ip)).s("\",");
	json.s("\"port\":").n(5060).s(",");
	json.s("\"httpPort\":").n(_port).s(",");
	// #411: which build is this. "version" is what tests/run.py's
	// board-provenance check and the bench run sheets compare with
	// `git describe` (TEST_HARNESS.md §5.3).
	//
	// Public, like the roster is not (#207): provenance fetches this without a
	// session, and a check that cannot see the field must not quietly pass.
	// ONLY the version string, by design -- the same class of disclosure as a
	// SIP User-Agent. No build host, no path, no build timestamp and no IDF
	// version here: those tell an attacker more than which build this is, and
	// provenance needs none of them. They go to the boot banner on the serial
	// console instead, which is not network-reachable.
	// Raw, no jsonEscape() (#461 review: it built a std::string per request).
	// cmake/FirmwareVersion.cmake refuses any stamp outside [A-Za-z0-9._+-] at
	// configure time, and FirmwareInfo_test pins the charset of the one built in.
	json.s("\"version\":\"").s(FirmwareInfo::version()).s("\",");
	// #529: HTTP connections dropped for a slow request, and refused because
	// one source already held its share of the slots.
	json.s("\"httpReadDeadlineDrops\":").n(readDeadlineDrops()).s(",");
	json.s("\"httpPerSourceRefusals\":").n(perSourceRefusals()).s(",");
	// #410: /api/status bodies refused for not fitting the fixed buffer.
	json.s("\"httpStatusRefusals\":").n(statusRefusals()).s(",");
	// #167: state the board's WiFi capability rather than leaving the dashboard
	// to infer it from an empty scan result. An eth/lan8720 build has no radio at
	// all, so "found 0 networks" is not an empty scan -- it is a scan that can
	// never succeed, and the two are indistinguishable to a client without this.
#if defined(POCKETDIAL_HAS_WIFI)
	json.s("\"wifiCapable\":true,");
#else
	json.s("\"wifiCapable\":false,");
#endif
	// Issue #521: where a 911 dial would go -- "anchor", "trunk" or "none".
	// "none" means the board refuses it with 503 (only the loopback simulator
	// is configured), and the dashboard keeps a warning banner up for as long
	// as it says so. Ungated like the rest of this block: whether this phone
	// system can reach 911 is something anyone at a handset is entitled to
	// know, and it names no host, account or credential.
	if (emergencyRoute != nullptr)
	{
		json.s("\"emergencyRoute\":\"").s(emergencyRoute).s("\",");
	}
	json.s("\"uptime\":").n(uptimeSec).s(",");
#if defined(ESP_PLATFORM)
	// Issue #496 / #509 review: frames and fragments the IPv4 input guard
	// (Ip4InputGuard.h) dropped since boot.
	{
		uint32_t g[3] = {0, 0, 0};
		pd_ip4_guard_counts(g);
		json.s("\"ip4Guard\":{\"padded\":").n(g[0]).s(",\"tinyFragments\":").n(g[1])
		    .s(",\"mdnsFragments\":").n(g[2]).s("},");
	}
#endif
	// #470: CDR ring persist health. A non-zero failure count means call history
	// is NOT surviving reboots; suppressed counts writes refused mid-reset (#473).
	json.s("\"cdrPersistFailures\":").n(CdrRing::persistFailureCount()).s(",");
	json.s("\"cdrPersistSuppressed\":").n(CdrRing::persistSuppressedCount()).s(",");
	json.s("\"cdrLoadFailures\":").n(CdrRing::loadFailureCount()).s(",");   // #594: load() read failures
	json.s("\"packetsProcessed\":").n(packets).s(",");
	json.s("\"packetsDropped\":").n(dropped).s(",");
	// Issue #409: draws refused by a spent pool (neither has a heap fallback).
	// The message pool is process-global, so it reads even with no engine.
	json.s("\"msgPoolRefusals\":").n(RequestsHandler::getMessagePoolRefusals()).s(",");
	json.s("\"vpeerPoolRefusals\":").n(handler ? handler->getVirtualPeerRefusals() : 0).s(",");
	// #702 item 19: two "should stay zero" counters that were test-only until now.
	json.s("\"repliesRefused\":").n(handler ? handler->getRepliesRefused() : 0).s(",");   // #424
	json.s("\"optionsPingTruncated\":").n(handler ? handler->getOptionsPingTruncated() : 0).s(",");   // #463
	json.s("\"byeTruncated\":").n(handler ? handler->getByeTruncated() : 0).s(",");   // #744
	// Issue #663: trunk responses dropped as not from the carrier (#617, #356).
	json.s("\"trunkForgedRegisterResponses\":").n(handler ? handler->getTrunkForgedRegisterResponses() : 0).s(",");
	json.s("\"trunkForgedDialogResponses\":").n(handler ? handler->getTrunkForgedDialogResponses() : 0).s(",");
	json.s("\"trunkRefusedDialogByes\":").n(handler ? handler->getTrunkRefusedDialogByes() : 0).s(",");
	// #741: 911/933 calls ended after 4 h with both legs silent.
	json.s("\"emergencyRtpReaps\":").n(handler ? handler->getEmergencyRtpReaps() : 0).s(",");
	// #864: ARP requests held back for unanswered Learn REGISTERs.
	json.s("\"learnArpRequestsLimited\":").n(handler ? handler->getLearnArpRequestsLimited() : 0).s(",");
	// #450 / poll #454: false after a factory reset until the E911 notify list is
	// set again. The dashboard shows a banner; nothing is gated on it.
	json.s("\"e911Configured\":").b(e911Configured).s(",");
	// Issue #430: the same drops by reason (they sum to packetsDropped, modulo a
	// race between the loads), then the most recent ones. Like the roster below
	// (#207), the per-drop source addresses and bytes need a session; the counts
	// do not.
	json.s("\"droppedInvalid\":").n(droppedInvalid).s(",");
	json.s("\"droppedRate\":").n(droppedRate).s(",");
	// Issue #430: CR/LF-only keep-alives. Counted apart: they are not drops.
	json.s("\"keepalivesCrlf\":").n(keepalivesCrlf).s(",");
	// Issue #443/#444: discarded before handle() -- NOT part of packetsDropped.
	// No message was ever built for these; the ring below records their source
	// (no_pool, oversize with the datagram's real length). recvErrors are failed
	// receives (no datagram, so no source); the receive timeout's idle wake is
	// not counted.
	json.s("\"droppedNoPool\":").n(droppedNoPool).s(",");
	json.s("\"droppedOversize\":").n(droppedOversize).s(",");
	// Issue #469: the RTP side of the same check -- media datagrams over
	// RtpReceiver::MAX_DATAGRAM_BYTES, dropped instead of parsed cut.
	json.s("\"rtpRxOversize\":").n(RtpReceiver::rxOversizeDrops()).s(",");
	// #479: tx stack pool starts refused (pool full) and slots retired at boot.
	json.s("\"rtpTxPoolRefused\":").n(RtpSender::txPoolRefusals()).s(",");
	json.s("\"rtpTxPoolRetired\":").n(RtpSender::txPoolRetired()).s(",");
	json.s("\"recvErrors\":").n(recvErrors).s(",");
	json.s("\"lastRecvErrno\":").n(lastRecvErrno).s(",");
	json.s("\"recentDrops\":[");
	if (authenticated && handler != nullptr)
	{
		// One Record on the stack at a time, no allocation, and the probe's lock
		// is held only for each copy, never across the formatting (DropProbe.hpp).
		const DropProbe& probe = handler->getDropProbe();
		uint32_t first = 0, end = 0;
		probe.window(first, end);
		bool any = false;
		for (uint32_t seq = first; seq != end; ++seq)
		{
			DropProbe::Record d;
			if (!probe.at(seq, d)) continue;   // evicted since window()
			static const char kHex[] = "0123456789abcdef";
			char head[2 * DropProbe::kHeadBytes + 1];
			const size_t headLen = (std::min)(static_cast<size_t>(d.headLen), DropProbe::kHeadBytes);
			for (size_t b = 0; b < headLen; b++)
			{
				head[2 * b]     = kHex[d.head[b] >> 4];
				head[2 * b + 1] = kHex[d.head[b] & 0x0f];
			}
			head[2 * headLen] = '\0';
			// "ip:port", as sipwire::addrToIpPort() formats it, without its std::string.
			in_addr srcAddr{};
			srcAddr.s_addr = d.ip;
			char srcIp[INET_ADDRSTRLEN] = "";
			if (inet_ntop(AF_INET, &srcAddr, srcIp, sizeof(srcIp)) == nullptr) srcIp[0] = '\0';
			if (any) json.s(",");
			any = true;
			json.s("{\"seq\":").n(d.seq)
			    .s(",\"tsUs\":").n(d.tsUs)
			    .s(",\"reason\":\"").s(DropProbe::reasonName(d.reason)).s("\"")
			    .s(",\"src\":\"").e(srcIp).s(":").n(ntohs(d.port)).s("\"")
			    .s(",\"len\":").n(d.len)
			    .s(",\"head\":\"").s(head).s("\"}");
		}
	}
	json.s("],");

	// microSD, on builds that have a slot wired (currently the T-ETH-ELITE `eth`
	// board only). Always present so a client can tell "no card" from "this build
	// has no slot": `present` is the build capability, `mounted` the runtime fact.
#if defined(PD_ETH_HAS_SD)
	json.s("\"sd\":{\"present\":true,\"mounted\":").b(pd_sd_mounted())
	    .s(",\"capacityMb\":").n(pd_sd_capacity_mb()).s("},");
#else
	json.s("\"sd\":{\"present\":false,\"mounted\":false,\"capacityMb\":0},");
#endif

	// #473: did the last factory reset complete? Public, like the counts: it
	// discloses no identity, and an operator taking the board over needs to
	// see it before logging in. `resetJournal` says where the record lives
	// ("flash" survives a power cut, "rtc" only a restart -- see ResetJournal.hpp).
	{
		const resetjournal::BootStatus rj = resetjournal::bootStatus();
		json.s("\"resetIncomplete\":").b(rj.incomplete()).s(",")
		    .s("\"resetIncompleteStage\":\"").s(resetjournal::stageName(rj.stage)).s("\",")
		    .s("\"resetFailedMask\":").n(static_cast<unsigned>(rj.failedMask)).s(",")
		    .s("\"resetJournal\":\"").s(resetjournal::storageName(rj.storage)).s("\",")
		    .s("\"resetJournalWriteFailures\":").n(resetjournal::writeFailureCount()).s(",");
	}

	// The snapshot tables, formatted in place under the snapshot lock (#410).
	// Nothing in here blocks: it only appends to the fixed buffer.
	auto tables = [&](const auto& snap)
	{
		// Clients array
		// #207: the roster is withheld from an unauthenticated caller. The counts
		// below stay visible -- "4 phones registered" is operational status, and the
		// dashboard shows it before login -- but WHICH extensions, at WHICH
		// addresses, is a target list and requires a session.
		json.s("\"clients\":[");
		for (size_t i = 0; authenticated && i < snap.clients.size(); i++)
		{
			if (i > 0) json.s(",");
			json.s("{\"number\":\"").e(snap.clients[i].first)
			    .s("\",\"address\":\"").e(snap.clients[i].second).s("\"}");
		}
		json.s("],");
		// The COUNT is not withheld -- "4 phones registered" is operational status the
		// dashboard shows before login, and it discloses no identity. Emitted
		// unconditionally so an unauthenticated client can tell "nobody is registered"
		// from "you are not allowed to see who is", which an empty array alone cannot.
		json.s("\"clientCount\":").n(snap.clients.size()).s(",");
		json.s("\"rosterVisible\":").b(authenticated).s(",");

		// Sessions array
		// Issue #539: live callers and callees are the CURRENT version of the CDR,
		// which #207 put behind the session gate -- so they follow the roster's
		// rule. An unauthenticated caller gets an empty array plus two identity-
		// free fields: how many calls are up, and how old the oldest one is (the
		// #401 soak tooling reads these to find a stuck leg without a credential).
		int oldestSessionSec = 0;
		for (const auto& s : snap.sessions)
		{
			oldestSessionSec = (std::max)(oldestSessionSec, std::get<3>(s));
		}
		json.s("\"sessionCount\":").n(snap.sessions.size()).s(",");
		json.s("\"oldestSessionSec\":").n(oldestSessionSec).s(",");
		json.s("\"sessions\":[");
		for (size_t i = 0; authenticated && i < snap.sessions.size(); i++)
		{
			if (i > 0) json.s(",");
			int durationSec = std::get<3>(snap.sessions[i]);
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

			json.s("{\"caller\":\"").e(std::get<0>(snap.sessions[i]))
			    .s("\",\"callee\":\"").e(std::get<1>(snap.sessions[i]))
			    .s("\",\"state\":\"").e(std::get<2>(snap.sessions[i]))
			    .s("\",\"duration\":\"").s(durationBuf).s("\"}");
		}
		json.s("],");

		// DND array: extensions currently in Do Not Disturb (Phase 2).
		json.s("\"dnd\":[");
		for (size_t i = 0; i < snap.dnd.size(); i++)
		{
			if (i > 0) json.s(",");
			json.s("\"").e(snap.dnd[i]).s("\"");
		}
		json.s("],");

		// Voicemail array (Issue #246): extensions currently voicemail-enabled.
		json.s("\"voicemail\":[");
		for (size_t i = 0; i < snap.voicemail.size(); i++)
		{
			if (i > 0) json.s(",");
			json.s("\"").e(snap.voicemail[i]).s("\"");
		}
		json.s("],");

		// Call-forward array (Class A sweep): per-extension always/busy/noanswer targets.
		json.s("\"forwards\":[");
		for (size_t i = 0; i < snap.forwards.size(); i++)
		{
			if (i > 0) json.s(",");
			json.s("{\"extension\":\"").e(std::get<0>(snap.forwards[i]))
			    .s("\",\"always\":\"").e(std::get<1>(snap.forwards[i]))
			    .s("\",\"busy\":\"").e(std::get<2>(snap.forwards[i]))
			    .s("\",\"noanswer\":\"").e(std::get<3>(snap.forwards[i])).s("\"}");
		}
		json.s("],");

		// Ring/hunt-group array (Class A sweep): group ext, mode, comma-joined members.
		json.s("\"groups\":[");
		for (size_t i = 0; i < snap.ringGroups.size(); i++)
		{
			if (i > 0) json.s(",");
			json.s("{\"extension\":\"").e(std::get<0>(snap.ringGroups[i]))
			    .s("\",\"mode\":\"").e(std::get<1>(snap.ringGroups[i]))
			    .s("\",\"members\":\"").e(std::get<2>(snap.ringGroups[i])).s("\"}");
		}
		json.s("],");

		// Dial-plan rules (Issue #69, stripDigits for the Trunk action Issue #165).
		// Emitted in TABLE ORDER — this array's order is load-bearing (first match
		// wins), unlike the sets above.
		json.s("\"dialplan\":[");
		for (size_t i = 0; i < snap.dialRules.size(); i++)
		{
			if (i > 0) json.s(",");
			json.s("{\"pattern\":\"").e(std::get<0>(snap.dialRules[i]))
			    .s("\",\"action\":\"").e(std::get<1>(snap.dialRules[i]))
			    .s("\",\"target\":\"").e(std::get<2>(snap.dialRules[i]))
			    .s("\",\"stripDigits\":").n(std::get<3>(snap.dialRules[i])).s("}");
		}
		json.s("],");

		// Parked calls: {orbit, parkedExt, parker, secondsParked} — Issue #65's
		// ParkOrbit::snapshotRows(onlyParked=true), used by the dashboard to tell
		// a parked jack apart from an idle or actively-connected one.
		// Issue #539: which extension is parked, and by whom, is identity too.
		// The count stays public.
		json.s("\"parkedCount\":").n(snap.parkedCalls.size()).s(",");
		json.s("\"parkedCalls\":[");
		for (size_t i = 0; authenticated && i < snap.parkedCalls.size(); i++)
		{
			if (i > 0) json.s(",");
			json.s("{\"orbit\":\"").e(std::get<0>(snap.parkedCalls[i]))
			    .s("\",\"parkedExt\":\"").e(std::get<1>(snap.parkedCalls[i]))
			    .s("\",\"parker\":\"").e(std::get<2>(snap.parkedCalls[i]))
			    .s("\",\"secondsParked\":").n(std::get<3>(snap.parkedCalls[i])).s("}");
		}
		json.s("]");
	};
	if (handler != nullptr)
	{
		handler->withSnapshot(tables);
	}
	else
	{
		// No engine yet: the same keys, empty (docs/API.md).
		json.s("\"clients\":[],\"clientCount\":0,\"rosterVisible\":").b(authenticated)
		    .s(",\"sessionCount\":0,\"oldestSessionSec\":0,\"sessions\":[],\"dnd\":[],"
		       "\"voicemail\":[],\"forwards\":[],\"groups\":[],\"dialplan\":[],"
		       "\"parkedCount\":0,\"parkedCalls\":[]");
	}

	// Issue #185: task-watchdog / heap / per-task stack telemetry. Purely
	// additive -- every key here is new; nothing above this line changed.
#if defined(ESP_PLATFORM)
	json.s(",\"freeHeap\":").n(esp_get_free_heap_size());
	json.s(",\"minFreeHeap\":").n(esp_get_minimum_free_heap_size());
	json.s(",\"minFreeHeapSpiram\":").n(heap_caps_get_minimum_free_size(MALLOC_CAP_SPIRAM));
	// Issue #273: internal (DRAM) low-water, reported separately. The two
	// figures above cannot show a DRAM shortage -- MALLOC_CAP_SPIRAM is PSRAM
	// by definition, and the all-caps minimum is dominated by 8 MB of PSRAM,
	// so a near-exhausted 320 KB of DRAM barely moves it. Task stacks and
	// lwIP pbufs live here and nowhere else.
	json.s(",\"minFreeHeapInternal\":").n(heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL));
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
	json.s(",\"freeHeapInternal\":").n(heap_caps_get_free_size(MALLOC_CAP_INTERNAL));
	json.s(",\"largestFreeBlockInternal\":").n(heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL));
	json.s(",\"freeHeapDma\":").n(heap_caps_get_free_size(MALLOC_CAP_DMA));
	json.s(",\"largestFreeBlockDma\":").n(heap_caps_get_largest_free_block(MALLOC_CAP_DMA));
	json.s(",\"resetReason\":\"").s(pdResetReasonString(esp_reset_reason())).s("\"");
	pdAppendHwmField(json, "stackHwm_sip_server_task", pdSipServerStackHwmBytes());
	pdAppendHwmField(json, "stackHwm_udp_receiver_task", pdStackHwmBytes(PD_UDP_RECEIVER_TASK_NAME));
	pdAppendHwmField(json, "stackHwm_rtp_media_tx", pdStackHwmBytes("rtp_media_tx"));
	pdAppendHwmField(json, "stackHwm_rtp_media_rx", pdStackHwmBytes("rtp_media_rx"));
	pdAppendHwmField(json, "stackHwm_conf_mix_tick", pdStackHwmBytes("conf_mix_tick"));
	// #657: 12 KB each by precedent, not measurement; these readings are what a
	// smaller stack would need. null unless the boot anchor is a real one.
	pdAppendHwmField(json, "stackHwm_tel_ctl0", pdStackHwmBytes("tel_ctl0"));
	pdAppendHwmField(json, "stackHwm_tel_ctl1", pdStackHwmBytes("tel_ctl1"));
	pdAppendHwmField(json, "stackHwm_tel_drop", pdStackHwmBytes("tel_drop"));
	pdAppendHwmField(json, "stackHwm_tel_sos", pdStackHwmBytes("tel_sos"));
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
	json.s(",\"freeHeap\":0,\"minFreeHeap\":0,\"minFreeHeapSpiram\":0,\"minFreeHeapInternal\":0"
	       ",\"freeHeapInternal\":0,\"largestFreeBlockInternal\":0"
	       ",\"freeHeapDma\":0,\"largestFreeBlockDma\":0,\"resetReason\":\"n/a\"");
	json.s(",\"stackHwm_sip_server_task\":null,\"stackHwm_udp_receiver_task\":null,"
	       "\"stackHwm_rtp_media_tx\":null,\"stackHwm_rtp_media_rx\":null,"
	       "\"stackHwm_conf_mix_tick\":null,\"stackHwm_tel_ctl0\":null,\"stackHwm_tel_ctl1\":null,"
	       "\"stackHwm_tel_drop\":null,\"stackHwm_tel_sos\":null,\"stackHwm_http_conn\":null");
#endif
	// Issue #405: the route class that produced the stackHwm_http_conn minimum
	// (never the raw path, see routeLabel). null on the host build and until a
	// connection has finished. Written straight into the buffer: no frame here,
	// this is the route the issue suspects of being the deepest.
	json.s(",\"httpConnWorstRoute\":");
	{
		std::lock_guard<std::mutex> lk(_httpConnWorstMutex);
		if (_httpConnWorstRoute[0] != '\0') json.s("\"").e(_httpConnWorstRoute).s("\"");
		else json.s("null");
	}
	// Issue #382: ungated for the same reason resetReason is -- "a dump exists,
	// N bytes" is the fact a bench run needs to notice an unwatched panic, and it
	// discloses nothing the reset reason above does not. The dump itself and its
	// summary stay behind /api/coredump*.
	{
		const CoreDumpStore::Info cd = CoreDumpStore::query();
		// `supported` (#514): false when the board has no coredump partition,
		// so "present":false is not misread as "no crash happened".
		json.s(",\"coredump\":{\"present\":").b(cd.present)
		    .s(",\"size\":").n(cd.size)
		    .s(",\"supported\":").b(cd.supported).s("}");
	}

	// Issue #328: L2 transmit-path health, in one object, on the UNGATED route.
	//
	// The proof run for #328 could establish that hold music was streaming at
	// exactly 50 pkt/s and that DMA heap was collapsing underneath it, but not
	// WHICH path carried the audio -- HoldMusic::runLoop() tries the L2 bypass
	// and falls back to sendto() silently, logging only if the sendto() itself
	// errors. "The pool is working" and "it has been falling back all along"
	// were externally indistinguishable. poolAllocations answers it directly:
	// during a hold it should climb at the tick rate, and if it does not, the
	// audio is going out the socket path the pool exists to avoid.
	//
	// Deliberately here rather than on the gated /api/moh: the consumer is a
	// diagnostic harness, and a harness that needs an admin session to read a
	// counter does not get run. These are operational counters in the same
	// category as the heap and stack figures already on this route -- no
	// configuration, no identities, nothing an unauthenticated caller learns
	// that freeHeapInternal does not already tell them.
	//
	// The pool numbers are live on BOTH platforms (it has a real host
	// implementation and is in the host test target). The MoH error counters
	// are -1 off-device, emitted as null per the stackHwm_* convention.
	json.s(",\"l2Tx\":{\"poolAllocations\":").n(l2rtp::DmaFramePool::getAllocations())
	    .s(",\"poolExhaustions\":").n(l2rtp::DmaFramePool::getExhaustions())
	    .s(",\"poolAvailable\":").n(l2rtp::DmaFramePool::available())
	    .s(",\"poolSize\":").n(static_cast<size_t>(l2rtp::DmaFramePool::kPoolSize));
	const long mohL2Err   = handler ? handler->holdMusicL2TxErrors() : -1;
	const long mohSockErr = handler ? handler->holdMusicTxErrors()   : -1;
	json.s(",\"mohL2Errors\":");
	if (mohL2Err < 0) json.s("null"); else json.n(mohL2Err);
	json.s(",\"mohSockErrors\":");
	if (mohSockErr < 0) json.s("null"); else json.n(mohSockErr);
	json.s("}");

	// Issue #466: memory placement. clipRefusals counts clip buffers refused
	// (PSRAM short on a PSRAM board, or over POCKETDIAL_CLIP_INTERNAL_MAX_BYTES
	// on one without); the two flags say which clip is now absent -- MoH plays
	// silence, deposits record without a greeting. psramFallbacks counts
	// PSRAM-preferred buffers (the jitter rings) that PSRAM could not hold and
	// internal DRAM had to -- always 0 on a board without PSRAM.
	json.s(",\"memory\":{\"clipRefusals\":").n(HoldMusic::clipRefusals())
	    .s(",\"mohClipRefused\":").b(handler && handler->holdMusicClipRefused())
	    .s(",\"greetingRefused\":").b(handler && handler->voicemailGreetingRefused())
	    .s(",\"psramFallbacks\":").n(psram::internalFallbacks().load(std::memory_order_relaxed))
	    .s(",\"dynamicTaskCreates\":").n(psram::dynamicTaskCreates().load(std::memory_order_relaxed))   // #479
	    .s("}");

	json.s("}");

	if (json.full)
	{
		_statusRefusals.fetch_add(1, std::memory_order_relaxed);
		sendResponse(sock, 500, "Internal Server Error", "application/json",
			"{\"error\":\"status response too large\"}");
		return;
	}
	sendResponse(sock, 200, "OK", "application/json", std::string_view(buf, json.len));
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
//     entry directly above /metrics, ~line 449) and returns MORE than this
//     page does -- the dial plan, forwards and group tables, and the session
//     and park COUNTS. (Since #207 the roster, and since #539 every live
//     session's caller/callee and the parked-call rows, need a session.)
//     Gating /metrics while that stays open would not withhold anything from
//     an anonymous peer on the link; it would only look like a control.
//     Operational detail does leak here, but it is a subset of what already
//     leaks next door.
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
	uint64_t unboundCaller = 0;   // #497
	uint64_t droppedInvalid = 0;   // Issue #430
	uint64_t droppedRate  = 0;
	uint64_t keepalivesCrlf = 0;   // Issue #430
	uint64_t droppedNoPool = 0;    // Issue #443/#444
	uint64_t droppedOversize = 0;
	uint64_t recvErrors = 0;
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
		droppedInvalid = handler->getDroppedInvalid();
		droppedRate  = handler->getDroppedRate();
		keepalivesCrlf = handler->getKeepalivesCrlf();
		const DropProbe& probe = handler->getDropProbe();
		droppedNoPool   = probe.count(DropProbe::Reason::NoPool);
		droppedOversize = probe.count(DropProbe::Reason::Oversize);
		recvErrors      = probe.recvErrorCount();
		sdpRejected  = handler->getSdpRejected();
		unboundCaller = handler->getUnboundCallerRefusals();
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
	//
	// #630: written into one of /api/status's fixed buffers (JsonOut is a plain
	// bounded appender; nothing here is JSON), so a scrape allocates nothing.
	// The body is ~3.5 KB, far under the smallest buffer (16 KB).
	std::atomic<bool>* busy = nullptr;
	char* buf = leaseStatusBuf(busy);
	if (buf == nullptr)
	{
		_statusRefusals.fetch_add(1, std::memory_order_relaxed);
		sendResponse(sock, 503, "Service Unavailable", "text/plain; charset=utf-8", "no metrics buffer\n");
		return;
	}
	struct Release
	{
		std::atomic<bool>* f;
		~Release() { f->store(false, std::memory_order_release); }
	} release{busy};   // held until the send below has finished reading buf
	JsonOut out{buf, (std::min)(_statusCap, kStatusBufBytes)};
	auto family = [&out](const char* name, const char* type, const char* help, uint64_t value) {
		out.s("# HELP ").s(name).s(" ").s(help).s("\n")
		   .s("# TYPE ").s(name).s(" ").s(type).s("\n")
		   .s(name).s(" ").n(value).s("\n");
	};
	auto gauge = [&family](const char* name, const char* help, uint64_t value) {
		family(name, "gauge", help, value);
	};
	auto counter = [&family](const char* name, const char* help, uint64_t value) {
		family(name, "counter", help, value);
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
	counter("pocketdial_packets_dropped_invalid_total",
	        "The malformed share of pocketdial_packets_dropped_total: null, or failing "
	        "isValidMessage() (issue #430).",
	        droppedInvalid);
	counter("pocketdial_packets_dropped_rate_total",
	        "The refused share of pocketdial_packets_dropped_total: allowlist or per-IP "
	        "rate limit (issue #430).",
	        droppedRate);
	counter("pocketdial_sip_keepalives_crlf_total",
	        "CR/LF-only SIP keep-alives (RFC 5626 ping, or a UDP NAT keep-alive) since boot. "
	        "Not drops: they are counted here instead of pocketdial_packets_dropped_total "
	        "(issue #430).",
	        keepalivesCrlf);
	counter("pocketdial_packets_dropped_no_pool_total",
	        "SIP datagrams discarded before parsing because the message pool was "
	        "spent (issue #443; no heap fallback since #409). Not in "
	        "pocketdial_packets_dropped_total.",
	        droppedNoPool);
	counter("pocketdial_packets_dropped_oversize_total",
	        "SIP datagrams longer than the receive buffer, refused rather than parsed "
	        "truncated (issue #444). Not in pocketdial_packets_dropped_total.",
	        droppedOversize);
	counter("pocketdial_sip_recv_errors_total",
	        "Failed SIP socket receives, excluding the receive timeout's idle wake "
	        "(issue #443).",
	        recvErrors);
	counter("pocketdial_sdp_rejected_total",
	        "SDP bodies refused by the admission gate since boot, whether answered 488 "
	        "or dropped silently (docs/THREAT_MODEL.md T-7).",
	        sdpRejected);
	counter("pocketdial_invite_unbound_caller_total",
	        "INVITEs refused 403 because they did not come from the address the calling "
	        "extension registered from (issue #497): spoofed callers, or a phone that moved "
	        "without re-registering.",
	        unboundCaller);

	// "text/plain; version=0.0.4" is THE exposition-format content type — the
	// version parameter is how a scraper picks its parser, so it is not
	// decorative. sendResponse passes the string through verbatim.
	if (out.full)
	{
		_statusRefusals.fetch_add(1, std::memory_order_relaxed);
		sendResponse(sock, 500, "Internal Server Error", "text/plain; charset=utf-8", "metrics response too large\n");
		return;
	}
	sendResponse(sock, 200, "OK", "text/plain; version=0.0.4; charset=utf-8", std::string_view(buf, out.len));
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
		if (!handler->forceDisconnect(ext))
		{
			// #714 (desmo): an admin kill never ends an emergency call.
			sendResponse(sock, 409, "Conflict", "application/json",
			             "{\"error\":\"extension is on an emergency call\"}");
			return;
		}
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

void HttpServer::sendApiCoreDumpInfo(int sock)
{
	// Issue #382. Reached only through requireAdmin() -- see the route table.
	const CoreDumpStore::Info info = CoreDumpStore::query();
	std::ostringstream json;
	json << "{\"supported\":" << (info.supported ? "true" : "false")
	     << ",\"present\":" << (info.present ? "true" : "false")
	     << ",\"size\":" << info.size;
	if (info.present)
	{
		const CoreDumpStore::Summary s = CoreDumpStore::summary();
		char pc[11];
		std::snprintf(pc, sizeof(pc), "0x%08x", static_cast<unsigned>(s.pc));
		json << ",\"valid\":" << (s.valid ? "true" : "false")
		     << ",\"task\":\"" << jsonEscape(s.task) << "\""
		     << ",\"pc\":\"" << pc << "\""
		     << ",\"elfSha\":\"" << jsonEscape(s.elfSha) << "\""
		     << ",\"reason\":\"" << jsonEscape(s.reason) << "\"";
	}
	json << "}";
	sendResponse(sock, 200, "OK", "application/json", json.str());
}

void HttpServer::sendApiCoreDump(int sock)
{
	// Issue #382. Reached only through requireAdmin(..., Owner). The body is the
	// raw flash image (header + ELF + checksum), exactly what
	// `esp-coredump info_corefile -t raw -c <file> <SipServer.elf>` reads -- see
	// docs/COREDUMP.md.
	//
	// STREAMED in 1 KB chunks through one small INTERNAL-DRAM buffer, never
	// assembled whole. esp_flash_read() into anything that is not internal DRAM
	// (a whole-dump std::string lands in PSRAM, being above
	// SPIRAM_MALLOC_ALWAYSINTERNAL) borrows its own internal temp buffer of up
	// to 16 KB for the whole read (esp_flash_api.c, MAX_READ_CHUNK) -- internal
	// DRAM being exactly what #328 runs out of. A DRAM destination takes the
	// direct-read path instead. Found in review by BigDog on PR #394.
	//
	// The buffer is a STATIC in .bss (internal DRAM), not heap -- no dynamic
	// allocation on a request path, ever (desmo) -- and not stack, since these
	// per-connection threads have measured as little as 472 bytes free (#405).
	// One buffer means one download at a time; a second concurrent one gets
	// 503 rather than waiting, so no connection thread ever blocks on another.
	static constexpr size_t kChunk = 1024;
	static uint8_t s_chunk[kChunk];
	static std::mutex s_chunkMutex;
	std::unique_lock<std::mutex> chunkLock(s_chunkMutex, std::try_to_lock);
	if (!chunkLock.owns_lock())
	{
		sendResponse(sock, 503, "Service Unavailable", "application/json",
			"{\"error\":\"another coredump download is in progress\"}");
		return;
	}
	const CoreDumpStore::Info info = CoreDumpStore::query();
	if (!info.present)
	{
		sendResponse(sock, 404, "Not Found", "application/json",
			std::string("{\"error\":\"") + (info.supported ? "no coredump stored" : "coredump not supported") + "\"}");
		return;
	}
	uint8_t* const buf = s_chunk;
	// Read the first chunk BEFORE committing to a 200, so an early flash
	// failure is still a clean 500 rather than a truncated download.
	size_t len = std::min(kChunk, static_cast<size_t>(info.size));
	if (!CoreDumpStore::read(0, buf, len))
	{
		sendResponse(sock, 500, "Internal Server Error", "application/json",
			"{\"error\":\"coredump read failed\"}");
		return;
	}
	// The head and the first chunk go out together, in place (#410): no
	// std::string head any more -- this was the last one built.
	{
		HeadNumbers nums;
		SendPiece v[kHeadPieces + 1];
		size_t n = headPieces(v, nums, 200, "OK", "application/octet-stream", info.size,
			"Content-Disposition: attachment; filename=\"pocket-dial-coredump.bin\"");
		if (n == 0) return;
		if (len > 0)
		{
			v[n].iov_base = buf;
			v[n].iov_len = len;
			++n;
		}
		if (!sendAllPieces(sock, v, n)) return;
	}
	for (uint32_t off = static_cast<uint32_t>(len); off < info.size;)
	{
		len = std::min(kChunk, static_cast<size_t>(info.size - off));
		// A mid-stream failure can no longer change the status line; stopping
		// short of Content-Length is what tells the client the body is bad.
		if (!CoreDumpStore::read(off, buf, len)) return;
		if (!sendAllBytes(sock, reinterpret_cast<const char*>(buf), len)) return;
		off += static_cast<uint32_t>(len);
	}
}

void HttpServer::sendApiCoreDumpErase(int sock)
{
	// Issue #382. Reached only through requireAdmin(..., needCsrf=true).
	const CoreDumpStore::Info info = CoreDumpStore::query();
	if (!info.supported)
	{
		sendResponse(sock, 404, "Not Found", "application/json",
			"{\"error\":\"coredump not supported\"}");
		return;
	}
	const bool ok = CoreDumpStore::erase();
	sendResponse(sock, ok ? 200 : 500, ok ? "OK" : "Internal Server Error", "application/json",
		std::string("{\"erased\":") + (ok ? "true" : "false") + "}");
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
		     << "\"text\":\"" << jsonEscape(r.text) << "\","
		     << "\"truncated\":" << (r.truncated ? "true" : "false") << "}";
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

	// 4a. snom: snom<12 hex>.xml (20 chars, Issue #826). The PnP NOTIFY hands a
	// snom this URL with the MAC already lowercased, but a snom's own {mac}
	// template expands to UPPERCASE, so an admin-typed setting_server URL arrives
	// that way: accept either case here and key the lookup on the lowercase form.
	if (filename.size() == 20 && filename.compare(0, 4, "snom") == 0 &&
	    filename.compare(16, 4, ".xml") == 0)
	{
		std::string mac = filename.substr(4, 12);
		std::transform(mac.begin(), mac.end(), mac.begin(),
			[](unsigned char c) { return static_cast<char>(std::tolower(c)); });
		if (is12LowerHex(mac)) { outKey = mac; return ProvisioningPathType::Snom; }
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

	// 3. MAC-keyed provisioning paths (Yealink, Grandstream, PolycomPhone, CiscoSpaMac, Snom)
	auto info = handler ? handler->findProvisioningInfo(key) : std::nullopt;
	if (!info && handler != nullptr)
	{
		// Issue #826 part B: zero-touch. An unknown MAC may be assigned the next
		// free extension, but only for the host that IS that MAC: the TCP peer's
		// ARP entry must name it, so a fetch can never claim someone else's.
		// Every refusal (no window, wrong MAC, ARP miss, no token, no room, no
		// free extension) is the same 404 as an unknown MAC (THREAT_MODEL 4.3).
		bool verified = false;
		sockaddr_in peer{};
		peer.sin_family = AF_INET;
		if (!req.clientIp.empty() && inet_pton(AF_INET, req.clientIp.c_str(), &peer.sin_addr) == 1)
		{
			const auto peerMac = ArpLookup::pdLookupMac(peer);
			verified = peerMac.has_value() && ArpLookup::toHex12(*peerMac) == key;
		}
		std::string assigned;
		if (handler->autoAssign(key, verified, assigned))
		{
			info = handler->findProvisioningInfo(key);
		}
	}
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
	else if (type == ProvisioningPathType::Snom)
	{
		cfg = provisioning::snomConfigFor(info->extension, activeIp, 5060, info->authRequired);
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

// The E911 route's charset gate, shared with the config import (#483).
// nullptr when both fields pass, else the reason.
static const char* e911ConfigError(const std::string& exts, const std::string& callback)
{
	for (const std::string& e : pbx::splitMembers(exts))
	{
		if (!pbx::isDialTokenSafe(e)) return "notifyExts may contain only extensions, separated by spaces or commas";
	}
	if (!callback.empty() && !pbx::isDialTokenSafe(callback))
	{
		return "callback may contain only digits, letters, '#' and '*'";
	}
	return nullptr;
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

	if (const char* err = e911ConfigError(exts, callback))
	{
		sendResponse(sock, 400, "Bad Request", "application/json",
		             std::string("{\"error\":\"") + err + "\"}");
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

	// #410: no heap. The body is at most 78 bytes (both numbers at 20 digits), so
	// a small stack buffer holds it; a body that did not fit would be refused
	// with a 500, never truncated or grown.
	char buf[96];
	JsonOut json{buf, sizeof(buf)};
	json.s("{\"enabled\":").b(enabled)
	    .s(",\"route\":").n(route)
	    .s(",\"maxRoute\":").n(TelephonyApiConfig::kSlots)
	    .s("}");
	if (json.full)
	{
		sendResponse(sock, 500, "Internal Server Error", "application/json",
		             "{\"error\":\"sbc-mode response too large\"}");
		return;
	}
	sendResponse(sock, 200, "OK", "application/json", std::string_view(buf, json.len));
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
	// #652: a reset restarts the board, which would drop a live 911/933.
	if (RequestsHandler* h = _handler.load(std::memory_order_acquire); h && h->hasLiveEmergencyCall()) {
		sendResponse(sock, 409, "Conflict", "application/json", "{\"error\":\"emergency call in progress\"}");
		return;
	}
	// #473: from here on, NVS writers refuse new data (the CDR persist writer
	// first), so nothing a background task writes can put PII back behind this
	// reset. The board restarts at the end, which is what clears the flag.
	resetguard::begin();
	// #473: then open the reset journal, outside NVS, so that if anything below
	// fails -- or power is cut before the restart task closes it -- the next
	// boot reports the reset as incomplete (/api/status "resetIncomplete").
	// A journal write failure is logged and counted inside begin(); the reset
	// proceeds regardless (#481 review).
	(void)resetjournal::begin();
#if defined(POCKETDIAL_RESET_INTERRUPT_PROBE) && defined(ESP_PLATFORM)
	// BENCH-ONLY (#451 P4, #473): stands in for a power cut in the middle of a
	// reset, which nobody can pull on a remote bench. The journal is open and
	// nothing is erased yet, so this restart is exactly "the reset began and
	// never finished": the next boot must report resetIncomplete, with the
	// record surviving the restart from flash (resetJournal:"flash"). Nothing
	// is wiped, so the board keeps its config. Never ship it (CMake warns).
	ESP_LOGW("factory_reset", "RESET INTERRUPT PROBE: journal begun, restarting before any erase (#473)");
	esp_restart();
#endif
	// In-flight writes are drained before anything is erased.
	if (!resetguard::waitForWritersIdle(500))
	{
		std::cerr << "[reset] an NVS writer was still busy after 500 ms; erasing anyway" << std::endl;
	}
	// Clear the login credential, the DTMF PIN, and all sessions so the device
	// returns to the default-credential/needs-initial-setup state on both ESP
	// (NVS) and host (in-memory).
#if !(defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO))
	if (auto h = resetguard::beforeFirstEraseHookForTest()) h();   // #481 review: ordering pin
#endif
	const bool adminErased = AdminAuth::clearCredential();
	// Also drop ap_secure / ap_psk / cfgseed_gen. Clearing the seed generation is
	// deliberate: the next boot re-applies whatever the flasher wrote, so a
	// factory reset returns the board to how it was FLASHED rather than to a
	// hardcoded default the operator never chose.
	const bool deviceConfigCleared = DeviceConfig::clearAll();   // #441 review: reported below
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
	// above erases only its three named "storage" keys and resets reg_mode in
	// "pbxcfg" to learn (writeRegistrarMode(), src/Helpers/DeviceConfig.cpp; #397), and the
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
	// The ITSP trunk settings are the same story once more, and the stake is
	// higher: trunk_pass is a PLAINTEXT carrier password, and a carrier
	// password is a billable credential. It lives in "pbxcfg", which nothing
	// in this function otherwise reaches -- DeviceConfig::clearAll() erases
	// only its three named "storage" keys plus reg_mode, key by key, never a
	// namespace wipe. Without this line a factory-reset board handed to
	// someone else still has the previous operator's SIP trunk credential in
	// flash. Writing a default-constructed config over it is the store's own
	// documented "save always replaces" path, so it overwrites every trunk_*
	// key including the secret.
	//
	const bool trunkErased = TrunkConfigStore::save(TrunkConfigStore::Config{});
	// Issue #363: every other stored secret this function does not name --
	// smtp_pass/gsa_key, every extension's digest HA1, the last coredump. The
	// enumeration and the reasons live in FactoryReset.hpp.
	const bool secretsErased = FactoryReset::eraseStoredSecrets();

	bool forwardsErased = true;
	bool e911Erased = true;
	bool tapiErased = true;     // #456 review: the carrier OAuth client_secret lives here
	bool didmapErased = true;   // #456 review: the DID table is PII
	bool wifiErased = true;     // #456 review: wifi_pass etc. (radio builds only; true elsewhere)
	if (RequestsHandler* handler = _handler.load(std::memory_order_acquire))
	{
		// Both return "" on success, else the persist error (#456 review: these
		// results used to be discarded, so a failure still answered 200 "ok").
		tapiErased = handler->clearAllTelephonyConfig().empty();
		// #450: call-forward targets are external phone numbers (PII), in "pbxcfg",
		// which nothing above reaches.
		forwardsErased = handler->clearAllForwards();
		// Poll #454 (A): the E911 settings are PII and, after a reset, likely the
		// previous site's. Erased; /api/status then shows e911Configured:false and
		// boot logs a WARNING. Nothing is gated -- 911 still routes out.
		e911Erased = handler->clearE911Config();
		didmapErased = handler->clearAllDidMappings().empty();
		handler->clearAllCallHistory();
		// Push the now-empty trunk config into the running engine so the trunk
		// goes down immediately rather than at the next reboot.
		handler->applyStoredTrunkConfig();
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
	// #450: the SD voicemail archive (recordings, greetings, index), same
	// policy and same no-_mutex HTTP-task context as the CDR archive above.
	if (RequestsHandler* handler = _handler.load(std::memory_order_acquire))
	{
		handler->wipeAllVoicemail();
	}
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
	// so nothing outside this block may touch NVS directly -- except the
	// whole-partition erase in the restart task at the end (#450), which uses
	// nvs_flash.h from the ESP_PLATFORM include block.
	// #456 review: every erase is checked; NOT_FOUND (never set) is success.
	nvs_handle_t nvs_handle;
	const esp_err_t wifiOpen = nvs_open("storage", NVS_READWRITE, &nvs_handle);
	if (wifiOpen == ESP_OK) {
		for (const char* key : {"wifi_mode", "wifi_ssid", "wifi_pass", "decayed"})
		{
			const esp_err_t e = nvs_erase_key(nvs_handle, key);
			if (e != ESP_OK && e != ESP_ERR_NVS_NOT_FOUND) wifiErased = false;
		}
		if (nvs_commit(nvs_handle) != ESP_OK) wifiErased = false;
		nvs_close(nvs_handle);
	} else if (wifiOpen != ESP_ERR_NVS_NOT_FOUND) {
		wifiErased = false;
	}
#endif
	// #437 review: a secret-store erase that FAILED must not be reported as a
	// completed reset. The operator is about to hand this board on believing its
	// credentials are gone. The board still restarts: the admin credential is
	// already cleared above, so staying up half-reset helps nobody, and the reset
	// can be run again once setup completes. (DeviceConfig::clearAll()'s result is
	// deviceConfigCleared, #441.)
	// #441 (G-dubs's fold, taken over by Globox): the device-settings reset joins
	// this same check as "device" -- a failed reg_mode write can leave an old
	// `secure` in place, the lockout this reset exists to rescue.
	//
	// #473: each store that failed also goes into the reset journal, so the next
	// boot reports it even if this reply never reaches the operator. tapi, didmap,
	// wifi (#456 review) and the device settings (#441, #481 review) share the
	// journal's kOther bit.
	if (!adminErased)    resetjournal::noteFailure(resetjournal::kAdmin);
	if (!trunkErased)    resetjournal::noteFailure(resetjournal::kTrunk);
	if (!secretsErased)  resetjournal::noteFailure(resetjournal::kSecrets);
	if (!forwardsErased) resetjournal::noteFailure(resetjournal::kForwards);
	if (!e911Erased)     resetjournal::noteFailure(resetjournal::kE911);
	if (!tapiErased || !didmapErased || !wifiErased || !deviceConfigCleared)
		resetjournal::noteFailure(resetjournal::kOther);
	if (!adminErased || !trunkErased || !secretsErased || !forwardsErased || !e911Erased ||
		!tapiErased || !didmapErased || !wifiErased || !deviceConfigCleared)
	{
		// #450: one fixed format, filled on the stack -- no string building on the
		// HTTP task (#284). "failed" names each store, so the operator knows what
		// may still be in flash. Worst case 312 B of 384 (#456 review: tapi,
		// didmap and wifi added; #441: device).
		char body[384];
		const int n = std::snprintf(body, sizeof(body),
			"{\"status\":\"error\",\"failed\":{\"admin\":%s,\"trunk\":%s,\"secrets\":%s,\"forwards\":%s,\"e911\":%s,"
			"\"tapi\":%s,\"didmap\":%s,\"wifi\":%s,\"device\":%s},"
			"\"message\":\"Factory reset INCOMPLETE: the stores marked true under failed could not be erased. "
			"Rebooting anyway; run the factory reset again after setup.\"}",
			adminErased ? "false" : "true", trunkErased ? "false" : "true",
			secretsErased ? "false" : "true", forwardsErased ? "false" : "true",
			e911Erased ? "false" : "true", tapiErased ? "false" : "true",
			didmapErased ? "false" : "true", wifiErased ? "false" : "true",
			deviceConfigCleared ? "false" : "true");
		// A truncated or failed format must never ship as half a JSON object.
		static constexpr const char* kFallback =
			"{\"status\":\"error\",\"message\":\"Factory reset INCOMPLETE: one or more stores could "
			"not be erased. Rebooting anyway; run the factory reset again after setup.\"}";
		const bool formatted = n > 0 && static_cast<size_t>(n) < sizeof(body);
		sendResponse(sock, 500, "Internal Server Error", "application/json", formatted ? body : kFallback);
	}
	else
	{
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
	}
#if defined(ESP_PLATFORM)
	// Guarded on the platform, not the transport: esp_restart() and the deferred
	// restart task exist on every ESP build (see the include block at the top of
	// this file, which already makes exactly this distinction for the OTA path).
	// #450, poll #455 (A): end the same way the DTMF door does -- erase the WHOLE
	// NVS partition, then restart immediately. nvs_erase_key() above leaves the
	// old bytes readable in flash until page GC; nvs_flash_erase() takes the
	// pages. The per-key erases stay and are still reported: they are what the
	// response can speak to, and this is the backstop. Done in the restart task,
	// AFTER the response is sent and with nothing between the erase and the
	// restart, because every open NVS handle in other tasks is invalid from
	// here on. Keep-list checked on poll #455: nothing that must survive lives in
	// the nvs partition (cfgseed, prompts, coredump, otadata and phy_init are their
	// own partitions; a fresh boot re-runs PHY calibration, which is harmless).
	//
	// #473: the reset journal is closed here, the last step before the restart,
	// recording whether the whole-partition erase worked. The journal lives in
	// the prompts partition, which the NVS erase does not touch, so it survives
	// to the next boot; a hang or power cut before finish() leaves "interrupted".
	// 4096, not 2048 (#456 review): nvs_flash_erase()'s worst static chain is
	// ~1,920 B and finish() writes a flash sector; an overflow here would panic
	// mid-erase -- the half-reset state.
	if (xTaskCreate([](void* h) {
		vTaskDelay(pdMS_TO_TICKS(1000));
		// #473: the guard begun above still refuses new NVS data writes; drain any
		// write already in flight (the CDR persist writer) before the partition is
		// erased under it, as the DTMF door does.
		if (!resetguard::waitForWritersIdle(500))
		{
			ESP_LOGW("factory_reset", "an NVS writer was still busy after 500 ms; erasing anyway (#594)");
		}
		const esp_err_t eraseErr = nvs_flash_erase();
		if (eraseErr != ESP_OK)
		{
			ESP_LOGE("factory_reset", "nvs_flash_erase failed -- per-key erases stand, old NVS bytes may remain");
		}
		resetjournal::finish(eraseErr == ESP_OK ? 0 : resetjournal::kNvsErase);
		// #652: a 911/933 placed after the 409 check above would be dropped by the
		// restart; hold it until no emergency session is live, as the OTA reboot does.
		// Logged once, so an operator knows why the erased board has not rebooted.
		if (h && static_cast<RequestsHandler*>(h)->hasLiveEmergencyCall())
		{
			ESP_LOGW("factory_reset", "restart held: emergency call in progress (#652)");
			do vTaskDelay(pdMS_TO_TICKS(1000));
			while (static_cast<RequestsHandler*>(h)->hasLiveEmergencyCall());
		}
		esp_restart();
	}, "restart_task", 4096, _handler.load(std::memory_order_acquire), 5, NULL) != pdPASS)
	{
		// The reply has gone out and the per-key erases are done; without the task
		// there is no whole-partition erase, but the board must still restart
		// rather than stay up half-reset. Not erased here: this is the http_conn
		// stack, already deep (#458). The journal is deliberately NOT finished, so
		// it stays Begun and the next boot reports the reset as interrupted -- true.
		ESP_LOGE("factory_reset", "restart task not created -- restarting without the whole-NVS erase");
		vTaskDelay(pdMS_TO_TICKS(1000));
		esp_restart();
	}
#else
	// Host: no restart task, so the reset "completes" here.
	resetjournal::finish();
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
	}
	return "learn";
}

// "open" is NOT a mode any more (#500): the live setter answers 400 for it, and
// config import maps it to learn and says so (see sendApiConfigImport).
static bool parseRegistrarMode(const std::string& s, RequestsHandler::RegistrarMode& out)
{
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
		     << ",\"locked\":" << (d.locked ? "true" : "false")
		     << ",\"shared\":" << (d.shared ? "true" : "false")
		     << ",\"assigned\":" << (d.assigned ? "true" : "false")   // #826: zero-touch, unclaimed
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
		             "{\"error\":\"mode must be one of: learn, secure (open is retired)\"}");
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

// Issue #826. Written into a leased /api/status buffer with JsonOut: no heap,
// and the device table is visited in place rather than copied to this stack.
void HttpServer::sendApiPnp(int sock)
{
	RequestsHandler* handler = _handler.load(std::memory_order_acquire);
	if (handler == nullptr)
	{
		sendResponse(sock, 200, "OK", "application/json",
		             "{\"attached\":false,\"mode\":\"unknown\",\"devices\":[]}");
		return;
	}
	std::atomic<bool>* busy = nullptr;
	char* buf = leaseStatusBuf(busy);
	if (buf == nullptr)
	{
		_statusRefusals.fetch_add(1, std::memory_order_relaxed);
		sendResponse(sock, 503, "Service Unavailable", "application/json", "{\"error\":\"busy\"}");
		return;
	}
	struct Release
	{
		std::atomic<bool>* f;
		~Release() { f->store(false, std::memory_order_release); }
	} release{busy};
	JsonOut out{buf, (std::min)(_statusCap, kStatusBufBytes)};
	PnpResponder& pnp = handler->pnp();
	out.s("{\"attached\":true,\"mode\":\"").s(PnpResponder::modeName(pnp.mode())).s("\"");
	{
		const PnpResponder::Counters c = pnp.counters();
		std::array<char, 16> mask{};
		in_addr m{};
		m.s_addr = pnp.netmask();
		if (inet_ntop(AF_INET, &m, mask.data(), mask.size()) == nullptr) mask[0] = '\0';
		out.s(",\"listening\":").b(pnp.listening()).s(",\"socketErrno\":").n(pnp.socketErrno());
		out.s(",\"netmask\":\"").s(mask.data()).s("\",\"rx\":{\"datagrams\":").n(c.datagrams);
		out.s(",\"offSubnet\":").n(c.offSubnet).s(",\"notPnp\":").n(c.notPnp);
		out.s(",\"answered\":").n(c.answered).s("}");
	}
	out.s(",\"devices\":[");
	bool first = true;
	auto field = [](const std::array<char, pnp::kFieldCap>& a) {
		return std::string_view(a.data(), ::strnlen(a.data(), a.size()));
	};
	pnp.forEachDevice([&](const PnpResponder::Device& d) {
		std::array<char, 16> ip{};
		in_addr a{};
		a.s_addr = d.ip;
		if (inet_ntop(AF_INET, &a, ip.data(), ip.size()) == nullptr) ip[0] = '\0';
		out.s(first ? "{" : ",{");
		first = false;
		out.s("\"mac\":\"").s(std::string_view(d.id.mac.data(), pnp::kMacCap - 1));
		out.s("\",\"vendor\":\"").e(field(d.id.vendor)).s("\",\"model\":\"").e(field(d.id.model));
		out.s("\",\"version\":\"").e(field(d.id.version)).s("\",\"ip\":\"").s(ip.data());
		out.s("\",\"seen\":").n(d.seen).s(",\"lastSeen\":").n(d.lastSeen);
		out.s(",\"notified\":").b(d.notified).s("}");
	});
	out.s("]}");
	if (out.full)
	{
		sendResponse(sock, 500, "Internal Server Error", "application/json", "{\"error\":\"too large\"}");
		return;
	}
	sendResponse(sock, 200, "OK", "application/json", std::string_view(buf, out.len));
}

void HttpServer::sendApiPnpSet(int sock, const std::string& body)
{
	PnpResponder::Mode mode = PnpResponder::Mode::Off;
	if (!PnpResponder::parseMode(getFormParam(body, "mode"), mode))
	{
		sendResponse(sock, 400, "Bad Request", "application/json",
		             "{\"error\":\"mode must be one of: off, discover, provision\"}");
		return;
	}
	RequestsHandler* handler = _handler.load(std::memory_order_acquire);
	if (handler == nullptr)
	{
		sendResponse(sock, 503, "Service Unavailable", "application/json",
		             "{\"error\":\"SIP engine not attached yet\"}");
		return;
	}
	handler->pnp().setMode(mode);
	sendApiPnp(sock);
}

bool HttpServer::parseExtensionNumber(const std::string& s, uint32_t& out)
{
	if (s.size() < 3 || s.size() >= static_cast<size_t>(POCKETDIAL_MIN_PSTN_AOR_DIGITS)) return false;
	uint32_t n = 0;
	for (char c : s)
	{
		if (c < '0' || c > '9') return false;
		n = n * 10U + static_cast<uint32_t>(c - '0');
	}
	if (s[0] == '0') return false;   // "0123" would assign "123": refuse the ambiguity
	out = n;
	return true;
}

// Issue #826 part B. A small fixed body: no heap.
void HttpServer::sendApiZeroTouch(int sock)
{
	RequestsHandler* handler = _handler.load(std::memory_order_acquire);
	if (handler == nullptr)
	{
		sendResponse(sock, 200, "OK", "application/json", "{\"attached\":false,\"open\":false}");
		return;
	}
	const RequestsHandler::AutoAssignState s = handler->autoAssignState();
	std::array<char, 160> buf{};
	const int n = std::snprintf(buf.data(), buf.size(),
		"{\"attached\":true,\"open\":%s,\"lo\":%u,\"hi\":%u,\"secondsLeft\":%u,\"unclaimed\":%u,\"learnOnly\":true}",
		s.open ? "true" : "false", static_cast<unsigned>(s.lo), static_cast<unsigned>(s.hi),
		static_cast<unsigned>(s.secondsLeft), static_cast<unsigned>(s.unclaimed));
	if (n <= 0 || static_cast<size_t>(n) >= buf.size())
	{
		sendResponse(sock, 500, "Internal Server Error", "application/json", "{\"error\":\"too large\"}");
		return;
	}
	sendResponse(sock, 200, "OK", "application/json", std::string_view(buf.data(), static_cast<size_t>(n)));
}

void HttpServer::sendApiZeroTouchSet(int sock, const std::string& body)
{
	RequestsHandler* handler = _handler.load(std::memory_order_acquire);
	if (handler == nullptr)
	{
		sendResponse(sock, 503, "Service Unavailable", "application/json",
		             "{\"error\":\"SIP engine not attached yet\"}");
		return;
	}
	const std::string open = getFormParam(body, "open");
	if (open == "0")
	{
		handler->closeAutoAssign();
		sendApiZeroTouch(sock);
		return;
	}
	uint32_t lo = 0;
	uint32_t hi = 0;
	uint32_t minutes = 0;
	const std::string minutesText = getFormParam(body, "minutes");
	bool ok = open == "1" && parseExtensionNumber(getFormParam(body, "lo"), lo) &&
		parseExtensionNumber(getFormParam(body, "hi"), hi) && !minutesText.empty() && minutesText.size() <= 3;
	for (char c : minutesText) ok = ok && c >= '0' && c <= '9';
	if (ok) minutes = static_cast<uint32_t>(std::strtoul(minutesText.c_str(), nullptr, 10));
	if (!ok || !handler->openAutoAssign(lo, hi, minutes))
	{
		sendResponse(sock, 400, "Bad Request", "application/json",
		             "{\"error\":\"open=1 needs lo and hi (3-6 digits, lo <= hi, fewer than 500 apart) "
		             "and minutes (1-120); open=0 closes\"}");
		return;
	}
	sendApiZeroTouch(sock);
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

	if (action != "secure" && action != "forget")
	{
		sendResponse(sock, 400, "Bad Request", "application/json",
		             "{\"error\":\"action must be one of: secure, forget\"}");
		return;
	}

	// #820: two rows can hold one extension (a lock holder beside a later claim,
	// or a stale row). By extension, act only when exactly one does; otherwise
	// ask for the MAC, which is what the dashboard sends.
	{
		size_t holders = 0;
		for (const auto& d : handler->getAdoptedDevices())
		{
			if (d.mac == target) { holders = 0; break; }
			if (d.extension == target) ++holders;
		}
		if (holders > 1)
		{
			sendResponse(sock, 409, "Conflict", "application/json",
			             "{\"error\":\"more than one device holds that extension; send its MAC\"}");
			return;
		}
	}

	const bool ok = (action == "secure") ? handler->secureDevice(target) : handler->forgetDevice(target);

	if (!ok && action == "secure")
	{
		// Registrar::secure() refuses an extension with no SIP secret; say so
		// rather than claim the device does not exist.
		for (const auto& d : handler->getAdoptedDevices())
		{
			if ((d.mac == target || d.extension == target) && !SipSecretStore::hasSecret(d.extension))
			{
				sendResponse(sock, 409, "Conflict", "application/json",
				             "{\"error\":\"no SIP secret for ext " + d.extension + "\"}");
				return;
			}
		}
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
	// #484 review finding 5: wipe key material and HA1-bearing buffers once used.
	// volatile, so the compiler cannot drop the stores as dead.
	void secureWipe(void* p, size_t n)
	{
		volatile unsigned char* v = static_cast<volatile unsigned char*>(p);
		while (n--) *v++ = 0;
	}

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
//
// #483 section C: the ITSP trunk, SMTP, E911 and admin_ext, through the
// helpers their own routes use (defined with those routes below). The
// constrained 4 MB image has no room for it (#689); main/CMakeLists.txt sets 0.
#ifndef POCKETDIAL_BACKUP_SECTION_C
#define POCKETDIAL_BACKUP_SECTION_C 1
#endif
static std::string trunkConfigError(const TrunkConfigStore::Config& cfg, const std::string& ip);
#if POCKETDIAL_BACKUP_SECTION_C
namespace
{
	bool isValidEmailMode(const std::string& s);
	bool isValidEmailAuth(const std::string& s);
}
#endif
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

	// Issue #482: WHICH extensions are secured -- names only, the
	// secretSet-not-secret contract. Their HA1s are plaintext-EQUIVALENT (an
	// HA1 alone answers any digest challenge for that extension), so they
	// travel ONLY inside the password-encrypted `secretsEnc` block below, never
	// here: this part is served to any sysop and is also the encrypted
	// export's readable `plaintext` member. (#186's field list named them as
	// always-plaintext; that is the choice #482 reverses.)
	pt << "\"securedExtensions\":[";
	{
		bool first = true;
		for (const auto& ext : SipSecretStore::securedExtensions())
		{
			if (!SipSecretStore::hasSecret(ext)) continue;
			if (!first) pt << ",";
			first = false;
			pt << "\"" << jsonEscape(ext) << "\"";
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
	   << (handler ? registrarModeName(handler->getRegistrarMode()) : "learn") << "\",";

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

#if POCKETDIAL_BACKUP_SECTION_C
	// #483: the trunk and SMTP settings WITHOUT trunk_pass, smtp_pass and
	// gsa_key -- those travel in the secretsEnc block below and nowhere else.
	// Written straight into `pt`, not via trunkConfigJson()/emailConfigJson(),
	// which would each add two allocations to this #410-gated route.
	{
		const TrunkConfigStore::Config t = TrunkConfigStore::load();
		const EmailConfigStore::Config e = EmailConfigStore::load();
		pt << "\"trunk\":{\"host\":\"" << jsonEscape(t.host)
		   << "\",\"port\":" << t.port
		   << ",\"proxyHost\":\"" << jsonEscape(t.proxyHost)
		   << "\",\"proxyPort\":" << t.proxyPort
		   << ",\"fromUser\":\"" << jsonEscape(t.fromUser)
		   << "\",\"callerId\":\"" << jsonEscape(t.callerId)
		   << "\",\"authUser\":\"" << jsonEscape(t.authUser)
		   << "\",\"enabled\":" << (t.enabled ? "true" : "false")
		   << "},\"email\":{\"host\":\"" << jsonEscape(e.host)
		   << "\",\"port\":" << e.port
		   // Validated enums, nothing to escape (and "starttls" + 8 would push
		   // jsonEscape() out of the small-string buffer: one more allocation).
		   << ",\"mode\":\"" << (isValidEmailMode(e.mode) ? e.mode.c_str() : "")
		   << "\",\"auth\":\"" << (isValidEmailAuth(e.auth) ? e.auth.c_str() : "")
		   << "\",\"user\":\"" << jsonEscape(e.user)
		   << "\",\"from\":\"" << jsonEscape(e.from)
		   << "\",\"to\":\"" << jsonEscape(e.to)
		   << "\",\"gsaEmail\":\"" << jsonEscape(e.gsaEmail)
		   << "\",\"insecure\":" << (e.insecureSkipVerify ? "true" : "false")
		   << ",\"caPem\":\"" << jsonEscape(e.caPem) << "\"},";
	}
	if (handler)
	{
		std::string exts, callback, location;
		std::tie(exts, callback, location) = handler->getE911Config();
		pt << "\"e911\":{\"notifyExts\":\"" << jsonEscape(exts)
		   << "\",\"callback\":\"" << jsonEscape(callback)
		   << "\",\"location\":\"" << jsonEscape(location)
		   << "\"},\"adminExt\":\"" << jsonEscape(handler->getAdminExt()) << "\",";
	}
#endif

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
		gated << "]";
		// #482: the per-extension digest secrets (HA1s) live HERE and only here,
		// so a restore can bring secured extensions back (SipSecretStore::setHa1)
		// without ever putting them in the readable part of the file.
		gated << ",\"extensionSecrets\":[";
		{
			bool first = true;
			for (const auto& ext : SipSecretStore::securedExtensions())
			{
				auto ha1 = SipSecretStore::getHa1(ext);
				if (!ha1.has_value()) continue;
				if (!first) gated << ",";
				first = false;
				gated << "{\"extension\":\"" << jsonEscape(ext)
				      << "\",\"ha1\":\"" << jsonEscape(*ha1) << "\"}";
			}
		}
		gated << "]";
#if POCKETDIAL_BACKUP_SECTION_C
		// #483: the three secrets section C keeps out of the plaintext part.
		{
			const EmailConfigStore::Config email = EmailConfigStore::load();
			gated << ",\"trunkPass\":\"" << jsonEscape(TrunkConfigStore::load().pass)
			      << "\",\"smtpPass\":\"" << jsonEscape(email.pass)
			      << "\",\"gsaKey\":\"" << jsonEscape(email.gsaKey) << "\"";
		}
#endif
		gated << "}";
		std::string gatedPlaintext = gated.str();

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
		secureWipe(key, sizeof(key));
		secureWipe(&gatedPlaintext[0], gatedPlaintext.size());

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
		const bool opened = AdminAuth::aesGcmOpen(key, nonce.data(), aad, ctStr, plaintextOut);
		secureWipe(key, sizeof(key));
		if (!opened)
		{
			sendResponse(sock, 422, "Unprocessable Entity", "application/json",
			             "{\"error\":\"bad password or corrupted secrets block\"}");
			return;
		}

		std::string innerErr;
		const bool parsed = JsonReader::parse(plaintextOut, secretsValue, innerErr);
		if (!plaintextOut.empty()) secureWipe(&plaintextOut[0], plaintextOut.size());
		if (!parsed || !secretsValue.isObject())
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
	// #482: digest secrets come back ONLY from the decrypted secretsEnc block
	// (applied further below). An export from before #482 carried them in the
	// plaintext part: that file already leaked them, and it is not trusted as
	// a restore source -- say so instead of silently dropping them.
	if (!pt->arrayOr("extensionSecrets").empty())
	{
		skipped.push_back("extensionSecrets (legacy export carries digest secrets in CLEAR -- "
			"re-export with a password; see #482)");
	}
	const size_t securedListed = pt->arrayOr("securedExtensions").size();

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
		//
		// #500: an export from before the open registrar was retired may say
		// "open". Apply learn, the closest mode that still exists (it admits every
		// phone's first REGISTER), and say so, so the operator is not surprised.
		RequestsHandler::RegistrarMode parsedMode;
		// A blob with no registrarMode key leaves the mode as it is (BigDog's #502
		// review): defaulting a missing key would quietly drop a Secure board to
		// Learn, reported only under "applied". The empty string parses as no
		// mode, so nothing below applies it.
		std::string importedMode = pt->stringOr("registrarMode", "");
		if (importedMode.empty())
		{
			skipped.push_back("registrarMode (not in the file; left unchanged)");
		}
		if (importedMode == "open")
		{
			importedMode = "learn";
			skipped.push_back("registrarMode=open (the open registrar is retired; applied learn instead)");
		}
		if (parseRegistrarMode(importedMode, parsedMode))
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

		// #482: per-extension digest secrets, restored from the encrypted block
		// (owner-gated at the route, #484 review finding 1).
		//
		// #484 review finding 2: REPLACE means replace. When the file carries an
		// extensionSecrets list, a secured extension that is NOT in it loses its
		// secret, so a stale credential cannot survive the restore. Only when the
		// key is present: an encrypted export from before #482 has no such list,
		// and must not wipe every secret on the board. The count is capped at the
		// device's own client capacity, so a crafted file cannot flood the store.
		const JsonReader::Value* secretsList = secretsValue.find("extensionSecrets");
		if (secretsList != nullptr && secretsList->isArray())
		{
			const size_t cap = static_cast<size_t>(POCKETDIAL_MAX_CLIENTS);
			size_t restored = 0, rejected = 0, overCap = 0;
			std::vector<std::string> inFile;
			for (const auto& e : secretsValue.arrayOr("extensionSecrets"))
			{
				if (restored + rejected >= cap) { ++overCap; continue; }
				const std::string ext = e.stringOr("extension");
				if (SipSecretStore::setHa1(ext, e.stringOr("ha1"))) { ++restored; inFile.push_back(ext); }
				else ++rejected;
			}
			size_t cleared = 0;
			for (const auto& ext : SipSecretStore::securedExtensions())
			{
				if (std::find(inFile.begin(), inFile.end(), ext) == inFile.end() &&
					SipSecretStore::clearSecret(ext))
				{
					++cleared;
				}
			}
			if (restored > 0)
				applied.push_back("extensionSecrets (" + std::to_string(restored) + ")");
			if (cleared > 0)
				applied.push_back("extensionSecrets cleared (" + std::to_string(cleared) +
					" secured extension(s) not in the file)");
			if (rejected > 0)
				skipped.push_back("extensionSecrets (" + std::to_string(rejected) + " malformed entries)");
			if (overCap > 0)
				skipped.push_back("extensionSecrets (" + std::to_string(overCap) +
					" entries over the device's capacity of " + std::to_string(cap) + ")");
		}
	}
	else if (secretsEncNode)
	{
		skipped.push_back(password.empty()
			? "secretsEnc present but no password supplied"
			: "secretsEnc present but not applied");
	}
	// #482: secured extensions the export named but whose secrets did not come
	// back (a plaintext-only export, or no password) must be re-provisioned.
	if (!haveSecrets && securedListed > 0)
	{
		skipped.push_back("extensionSecrets (" + std::to_string(securedListed) +
			" secured extension(s): digest secrets travel only in the password-encrypted "
			"export -- re-export with a password, or re-set them)");
	}

#if POCKETDIAL_BACKUP_SECTION_C
	// #483 section C, held to the checks of each setting's own route. A key the
	// file lacks leaves that setting as it is. trunk_pass, smtp_pass and gsa_key
	// come back only from the decrypted secretsEnc block; without it the stored
	// ones are kept.
	const JsonReader::Value* sec = haveSecrets ? &secretsValue : nullptr;
	for (const char* key : { "trunk", "email", "e911", "adminExt" })
	{
		if (!pt->find(key)) skipped.push_back(std::string(key) + " (not in the file; left unchanged)");
	}
	if (!sec && (pt->find("trunk") || pt->find("email")))
	{
		skipped.push_back("trunk/SMTP passwords and gsaKey (only in the password-encrypted export; "
			"the stored ones are kept)");
	}
	if (const JsonReader::Value* t = pt->find("trunk"); t && t->isObject())
	{
		TrunkConfigStore::Config c = TrunkConfigStore::load();
		c.host      = t->stringOr("host");
		c.proxyHost = t->stringOr("proxyHost");
		c.fromUser  = t->stringOr("fromUser");
		c.callerId  = t->stringOr("callerId");
		c.authUser  = t->stringOr("authUser");
		c.enabled   = t->boolOr("enabled");
		if (sec) c.pass = sec->stringOr("trunkPass", c.pass);
		const int port = t->intOr("port", 0), proxyPort = t->intOr("proxyPort", 0);
		std::string err = "port must be 1-65535";
		if (port >= 1 && port <= 65535 && proxyPort >= 1 && proxyPort <= 65535)
		{
			c.port = static_cast<uint16_t>(port);
			c.proxyPort = static_cast<uint16_t>(proxyPort);
			err = trunkConfigError(c, _ip);
		}
		if (err.empty() && !TrunkConfigStore::save(c)) err = "failed to persist";
		if (!err.empty()) skipped.push_back("trunk (" + err + ")");
		else
		{
			applied.push_back("trunk");
			if (handler) handler->applyStoredTrunkConfig();   // as POST /api/trunk does
		}
	}
	if (const JsonReader::Value* e = pt->find("email"); e && e->isObject())
	{
		EmailConfigStore::Config c = EmailConfigStore::load();
		c.host     = e->stringOr("host");
		c.mode     = e->stringOr("mode");
		c.auth     = e->stringOr("auth");
		c.user     = e->stringOr("user");
		c.from     = e->stringOr("from");
		c.to       = e->stringOr("to");
		c.gsaEmail = e->stringOr("gsaEmail");
		c.insecureSkipVerify = e->boolOr("insecure");
		c.caPem    = e->stringOr("caPem");
		if (sec)
		{
			c.pass   = sec->stringOr("smtpPass", c.pass);
			c.gsaKey = sec->stringOr("gsaKey", c.gsaKey);
		}
		const int port = e->intOr("port", 0);
		if (port < 1 || port > 65535 || !isValidEmailMode(c.mode) || !isValidEmailAuth(c.auth))
		{
			skipped.push_back("email (port, mode or auth invalid)");
		}
		else
		{
			c.port = static_cast<uint16_t>(port);
			if (EmailConfigStore::save(c)) applied.push_back("email");
			else skipped.push_back("email (failed to persist)");
		}
	}
	if (handler)
	{
		if (const JsonReader::Value* e = pt->find("e911"); e && e->isObject())
		{
			const std::string exts = e->stringOr("notifyExts");
			const std::string callback = e->stringOr("callback");
			if (const char* err = e911ConfigError(exts, callback))
			{
				skipped.push_back(std::string("e911 (") + err + ")");
			}
			else
			{
				handler->setE911Config(exts, callback, e->stringOr("location"));
				applied.push_back("e911");
			}
		}
		if (pt->find("adminExt"))
		{
			if (handler->setAdminExt(pt->stringOr("adminExt"))) applied.push_back("adminExt");
			else skipped.push_back("adminExt (not a dial token of 1-31 characters, or not persisted)");
		}
	}
	else if (pt->find("e911") || pt->find("adminExt"))
	{
		skipped.push_back("e911/adminExt (SIP engine not attached yet)");
	}
#else
	if (pt->find("trunk")) skipped.push_back("trunk/email/e911/adminExt (not on this build, #689)");
#endif

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

// ---------------------------------------------------------------------
// Issue #164: ITSP SIP trunk configuration. See TrunkConfigStore.hpp for the
// persisted shape and the secret-handling rationale, SipTrunk.hpp for what the
// engine does with it.
//
// The password is write-only from here: the GET reports presence as a boolean
// and an empty submitted password means "keep the stored one", exactly as the
// /api/email routes above handle smtp_pass. That symmetry is deliberate --
// issue #207's bug class showed up twice in this project by treating one
// secret differently from another.
// ---------------------------------------------------------------------
namespace
{
	// Buffer ceilings enforced at the HTTP boundary rather than left to the
	// silent truncation in RequestsHandler::applyStoredTrunkConfig(). A trunk
	// that half-stores a 70-character password and then cannot authenticate,
	// with the UI cheerfully showing "set", is a support call nobody can
	// diagnose from the outside. These mirror SipTrunk::Config's arrays.
	constexpr size_t kMaxTrunkHost = 63;    // SipTrunk::Config::host[64]
	constexpr size_t kMaxTrunkFrom = 39;    // ...fromUser[40]
	constexpr size_t kMaxTrunkCid  = 23;    // ...callerId[24]
	constexpr size_t kMaxTrunkAuth = 63;    // ...authUser[64]
	constexpr size_t kMaxTrunkPass = 63;    // SipTrunk::kMaxSecret - 1

	// NO STRUCTURAL BACKSTOP HERE -- read this before adding a field.
	//
	// SipTrunk::Config cannot leak the password because it does not contain
	// one; that guarantee is structural and covers getTrunkConfig(). It does
	// NOT cover this function. This serializes TrunkConfigStore::Config, which
	// DOES hold `pass` in the clear, so the only things keeping the secret out
	// of the response are the discipline of not writing it below and
	// TrunkConfigHttp_test.cpp's GetNeverEchoesThePasswordEvenAuthenticated.
	// A new field added carelessly here is a #207 repeat with nothing to catch
	// it but that one test. Report presence as a boolean; never the value.
	std::string trunkConfigJson(const TrunkConfigStore::Config& cfg)
	{
		std::ostringstream json;
		json << "{\"host\":\"" << jsonEscape(cfg.host) << "\""
		     << ",\"port\":" << cfg.port
		     << ",\"proxyHost\":\"" << jsonEscape(cfg.proxyHost) << "\""
		     << ",\"proxyPort\":" << cfg.proxyPort
		     << ",\"fromUser\":\"" << jsonEscape(cfg.fromUser) << "\""
		     << ",\"callerId\":\"" << jsonEscape(cfg.callerId) << "\""
		     << ",\"authUser\":\"" << jsonEscape(cfg.authUser) << "\""
		     // Secret: presence only, NEVER the value -- issue #207's class.
		     << ",\"hasPassword\":" << (cfg.pass.empty() ? "false" : "true")
		     << ",\"enabled\":" << (cfg.enabled ? "true" : "false")
		     << "}";
		return json.str();
	}

	// Parses a port field. Empty leaves `out` at its current value, which is
	// how "the operator did not touch this" stays distinct from "set it to 0".
	bool parseTrunkPort(const std::string& raw, uint16_t& out)
	{
		if (raw.empty()) return true;
		char* end = nullptr;
		const long v = std::strtol(raw.c_str(), &end, 10);
		if (end == raw.c_str() || *end != '\0' || v < 1 || v > 65535) return false;
		out = static_cast<uint16_t>(v);
		return true;
	}
} // namespace

void HttpServer::sendApiTrunkConfig(int sock)
{
	sendResponse(sock, 200, "OK", "application/json",
	             trunkConfigJson(TrunkConfigStore::load()));
}


// Issue #546: true for a host that names this board itself -- loopback in any
// spelling this parser sees, or the board's own address. Such a trunk can
// never reach a carrier.
// #573 review: compared in place, no allocation on the HTTP task.
static bool asciiIEquals(std::string_view a, std::string_view b)
{
	if (a.size() != b.size()) return false;
	for (size_t i = 0; i < a.size(); ++i)
	{
		if (std::tolower(static_cast<unsigned char>(a[i])) != std::tolower(static_cast<unsigned char>(b[i])))
			return false;
	}
	return true;
}

static bool asciiIStartsWith(std::string_view s, std::string_view prefix)
{
	return s.size() >= prefix.size() && asciiIEquals(s.substr(0, prefix.size()), prefix);
}

static bool isSelfTrunkHost(std::string_view host, std::string_view ownIp)
{
	if (host.empty()) return false;
	for (std::string_view loop : { "localhost", "localhost.", "::1", "[::1]", "0.0.0.0" })
	{
		if (asciiIEquals(host, loop)) return true;
	}
	if (asciiIStartsWith(host, "127.") || asciiIStartsWith(host, "::ffff:127.") ||
		asciiIStartsWith(host, "[::ffff:127.")) return true;
	return !ownIp.empty() && ownIp != "0.0.0.0" && asciiIEquals(host, ownIp);
}

void HttpServer::sendApiTrunkConfigSet(int sock, const std::string& body)
{
	TrunkConfigStore::Config cfg = TrunkConfigStore::load(); // start from stored -- see the password merge below

	cfg.host      = getFormParam(body, "host");
	cfg.proxyHost = getFormParam(body, "proxyHost");
	cfg.fromUser  = getFormParam(body, "fromUser");
	cfg.callerId  = getFormParam(body, "callerId");
	cfg.authUser  = getFormParam(body, "authUser");

	const std::string enabledParam = getFormParam(body, "enabled");
	cfg.enabled = (enabledParam == "1" || enabledParam == "on" || enabledParam == "true");

	if (!parseTrunkPort(getFormParam(body, "port"), cfg.port) ||
	    !parseTrunkPort(getFormParam(body, "proxyPort"), cfg.proxyPort))
	{
		sendResponse(sock, 400, "Bad Request", "application/json",
		             "{\"error\":\"port must be 1-65535\"}");
		return;
	}

	// Secret: an empty submitted value means "leave the stored one alone". The
	// dashboard never re-displays the password, so there is nothing for the
	// client to redact from and a blank field must not read as "clear this".
	// Clearing is an explicit act -- clearPassword=1.
	const std::string pass = getFormParam(body, "pass");
	if (getFormParam(body, "clearPassword") == "1") cfg.pass.clear();
	else if (!pass.empty())                          cfg.pass = pass;

	const std::string err = trunkConfigError(cfg, _ip);
	if (!err.empty())
	{
		sendResponse(sock, 400, "Bad Request", "application/json", "{\"error\":\"" + err + "\"}");
		return;
	}

	if (!TrunkConfigStore::save(cfg))
	{
		sendResponse(sock, 500, "Internal Server Error", "application/json",
		             "{\"error\":\"failed to persist trunk configuration\"}");
		return;
	}

	// Apply to the running engine. Persisting without applying would leave the
	// live trunk pointed at the previous carrier until the next reboot -- the
	// kind of bug that only surfaces mid-cutover.
	if (RequestsHandler* h = _handler.load(std::memory_order_acquire))
	{
		h->applyStoredTrunkConfig();
	}

	sendResponse(sock, 200, "OK", "application/json",
	             "{\"status\":\"ok\",\"config\":" + trunkConfigJson(cfg) + "}");
}

// The trunk route's checks on a parsed config, shared with the config import
// (#483). Empty when the config may be saved, else the reason.
static std::string trunkConfigError(const TrunkConfigStore::Config& cfg, const std::string& ip)
{
	struct { const char* name; const std::string& val; size_t cap; } limits[] = {
		{ "host",      cfg.host,      kMaxTrunkHost },
		{ "proxyHost", cfg.proxyHost, kMaxTrunkHost },
		{ "fromUser",  cfg.fromUser,  kMaxTrunkFrom },
		{ "callerId",  cfg.callerId,  kMaxTrunkCid  },
		{ "authUser",  cfg.authUser,  kMaxTrunkAuth },
		{ "pass",      cfg.pass,      kMaxTrunkPass },
	};
	for (const auto& l : limits)
	{
		if (l.val.size() > l.cap)
		{
			std::ostringstream err;
			err << l.name << " must be at most " << l.cap << " characters";
			return err.str();
		}
	}

	// Enabling a trunk that cannot possibly place a call is a misconfiguration
	// worth refusing at the door rather than discovering when someone dials 9.
	// These are exactly SipTrunk::Config::valid()'s requirements; saving them
	// inconsistent would leave the UI showing "enabled" beside a trunk the
	// engine silently treats as invalid.
	if (cfg.enabled && (cfg.host.empty() || cfg.fromUser.empty()))
	{
		return "host and fromUser are required to enable the trunk";
	}

	// Issue #546: a trunk pointed at this board itself -- loopback, or its own
	// address -- can never reach a carrier, yet it would satisfy valid() and
	// report an emergency route. Refuse it at the door, like the check above.
	{
		char ownIp[INET_ADDRSTRLEN] = {0};   // #573 review: fixed buffer, no std::string
		if (ip == "0.0.0.0") (void)getPrimaryLocalIPInto(ownIp, sizeof(ownIp));
		else (void)std::snprintf(ownIp, sizeof(ownIp), "%s", ip.c_str());
		for (const std::string* h : { &cfg.host, &cfg.proxyHost })
		{
			if (isSelfTrunkHost(*h, ownIp))
			{
				return "the trunk host must be the carrier, not this board (loopback or its own address)";
			}
		}
	}
	return {};
}

// The two standalone setup pages: one flash part each, streamed in place with
// the CSRF token substituted on the way out (#410). They used to copy the whole
// page (~7.7 KB / ~10.5 KB) into a std::string -- under the 16 KB
// SPIRAM_MALLOC_ALWAYSINTERNAL line, so from internal DRAM, #328's constraint.
void HttpServer::sendTrunkSetupHtml(int sock, const HttpRequest& req)
{
	const char* parts[] = { PD_HTML_9 };
	const size_t sizes[] = { sizeof(PD_HTML_9) - 1 };
	const std::string token = AdminAuth::sessionCsrf(sessionToken(req));
	sendStaticHtml(sock, parts, sizes, 1, token);
}

void HttpServer::sendEmailSetupHtml(int sock, const HttpRequest& req)
{
	const char* parts[] = { PD_HTML_8 };
	const size_t sizes[] = { sizeof(PD_HTML_8) - 1 };
	const std::string token = AdminAuth::sessionCsrf(sessionToken(req));
	sendStaticHtml(sock, parts, sizes, 1, token);
}

#if !defined(ESP_PLATFORM) && !defined(ESP32) && !defined(ARDUINO)
void HttpServer::servePageForTest(int sock, int page, const std::string& cookieHeader)
{
	HttpRequest req;
	req.cookie = cookieHeader;
	if (page == 0)      sendHtml(sock, req);
	else if (page == 8) sendEmailSetupHtml(sock, req);
	else if (page == 9) sendTrunkSetupHtml(sock, req);
}

std::string HttpServer::csrfForTest(const std::string& cookieHeader)
{
	HttpRequest req;
	req.cookie = cookieHeader;
	return AdminAuth::sessionCsrf(sessionToken(req));
}

std::string HttpServer::legacyHtmlHeadForTest(size_t len)
{
	return buildResponseHead(200, "OK", "text/html; charset=utf-8", len, "");
}

void HttpServer::sendResponseForTest(int sock, int statusCode, std::string_view statusText,
                                     std::string_view contentType, std::string_view body,
                                     std::string_view extraHeader)
{
	sendResponseWithHeader(sock, statusCode, statusText, contentType, body, extraHeader);
}

std::string HttpServer::legacyResponseForTest(int statusCode, const std::string& statusText,
                                              const std::string& contentType, const std::string& body,
                                              const std::string& extraHeader)
{
	return buildResponseHead(statusCode, statusText, contentType, body.size(), extraHeader) + body;
}
#endif

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

#if defined(POCKETDIAL_ANCHOR_BENCH_PROBE) && defined(ESP_PLATFORM)
// #384 H1: arm one fault, or hold or release the DRAM ballast, then answer with
// every counter; a GET only reads them. Reached only through requireAdmin(...,
// Owner). The body goes through one static buffer: http_conn stacks are tight
// (#405, #457).
void HttpServer::sendApiBenchFault(int sock, const HttpRequest& req)
{
	namespace bp = pd::benchprobe;
	bp::Verdict v = bp::Verdict::Ok;
	if (req.method == "POST")
	{
		RequestsHandler* h = _handler.load(std::memory_order_acquire);
		const bool emergency = h && h->hasLiveEmergencyCall();
		const std::string fault = getFormParam(req.body, "fault");
		const std::string ballast = getFormParam(req.body, "ballast");
		if (!fault.empty() && ballast.empty())
			v = bp::armFault(fault, getFormParam(req.body, "value"), emergency);
		else if (fault.empty() && ballast == "release")
			bp::releaseBallast();
		else if (fault.empty() && !ballast.empty())
			v = bp::armBallast(ballast, getFormParam(req.body, "deadman"), emergency);
		else
			v = bp::Verdict::BadRequest;
	}
	switch (v)
	{
		case bp::Verdict::Ok:
			break;
		case bp::Verdict::BadRequest:
			sendResponse(sock, 400, "Bad Request", "application/json",
				"{\"error\":\"fault[,value] or ballast[,deadman] or ballast=release (docs/BENCH_PROBE.md)\"}");
			return;
		case bp::Verdict::EmergencyLive:
			sendResponse(sock, 409, "Conflict", "application/json", "{\"error\":\"emergency call in progress\"}");
			return;
		case bp::Verdict::Busy:
			sendResponse(sock, 409, "Conflict", "application/json", "{\"error\":\"ballast already held\"}");
			return;
		case bp::Verdict::NoMemory:
			sendResponse(sock, 503, "Service Unavailable", "application/json", "{\"error\":\"no dead-man timer\"}");
			return;
	}
	static char s_body[1024];
	static std::mutex s_bodyMutex;
	std::unique_lock<std::mutex> lock(s_bodyMutex, std::try_to_lock);
	const size_t n = lock.owns_lock() ? bp::renderStatus(s_body, sizeof(s_body)) : 0;
	if (n == 0)
	{
		sendResponse(sock, 503, "Service Unavailable", "application/json", "{\"error\":\"counters busy\"}");
		return;
	}
	sendResponse(sock, 200, "OK", "application/json", std::string_view(s_body, n));
}
#endif

void HttpServer::sendApiOtaReboot(int sock, const std::string& body)
{
	// #645: with no staged image (boot == running partition) this is a plain
	// restart. It used to answer 409, which left the dashboard's confirmed
	// Reboot button no way to restart the device. requireAdmin (session + CSRF)
	// still gates the route. Decided outside the ESP guard so the host tests it.
	const bool staged = OtaUpdater::bootPartitionLabel() != OtaUpdater::runningPartitionLabel();
	// A plain reboot drops live calls (911 included), so it needs an explicit
	// confirm token, like confirm=ERASE on /api/factory-reset. A staged-OTA
	// reboot keeps its old no-parameter behaviour.
	if (!staged && getFormParam(body, "confirm") != "1") {
		sendResponse(sock, 400, "Bad Request", "application/json",
		             "{\"error\":\"reboot with no staged image requires confirm=1\"}");
		return;
	}
	// #652: a manual reboot during a live 911/933 is refused; a staged-image
	// reboot is accepted and waits in the restart task below for the call to end.
	RequestsHandler* handler = _handler.load(std::memory_order_acquire);
	if (!staged && handler && handler->hasLiveEmergencyCall()) {
		sendResponse(sock, 409, "Conflict", "application/json", "{\"error\":\"emergency call in progress\"}");
		return;
	}
	std::string json = std::string("{\"status\":\"ok\",\"staged\":") + (staged ? "true" : "false");
#if defined(ESP_PLATFORM)
	json += staged ? ",\"message\":\"rebooting into the new image...\"}" : ",\"message\":\"rebooting...\"}";
	sendResponse(sock, 200, "OK", "application/json", json);

	// Defer the restart so the HTTP response flushes first (mirrors the WiFi
	// connect/mode endpoints' delayed-restart pattern).
	xTaskCreate([](void* h) {
		vTaskDelay(pdMS_TO_TICKS(1000));
		// #652: hold the restart while any emergency call is live, and say so once.
		if (h && static_cast<RequestsHandler*>(h)->hasLiveEmergencyCall())
		{
			ESP_LOGW("ota_reboot", "restart held: emergency call in progress (#652)");
			do vTaskDelay(pdMS_TO_TICKS(1000));
			while (static_cast<RequestsHandler*>(h)->hasLiveEmergencyCall());
		}
		esp_restart();
	}, "ota_reboot", 4096, handler, 5, NULL);   // #677: ESP_LOGW -> vprintf needs more than 2048 B
#else
	// Host stub: never actually exit the process (the smoke-test harness keeps
	// running). Report a simulated success.
	json += ",\"simulated\":true,\"message\":\"reboot is a no-op on the desktop build\"}";
	sendResponse(sock, 200, "OK", "application/json", json);
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
