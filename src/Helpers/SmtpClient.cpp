#include "SmtpClient.hpp"

#include <cstring>
#include <mutex>

#if defined(__linux__) || defined(ESP_PLATFORM)
	#include <unistd.h>
	#include <sys/types.h>
	#include <sys/socket.h>
	#include <netinet/in.h>
	#include <netinet/tcp.h>
	#include <arpa/inet.h>
	#include <netdb.h>
	#include <fcntl.h>
	#include <errno.h>
	#define PD_SMTP_CLOSESOCK(s) ::close(s)
#elif defined _WIN32 || defined _WIN64
	#include <WinSock2.h>
	#include <WS2tcpip.h>
	#pragma comment(lib, "ws2_32.lib")
	#define PD_SMTP_CLOSESOCK(s) closesocket(s)
#endif

#if defined(ESP_PLATFORM) || defined(ESP32)
	#include "esp_crt_bundle.h"
	#include "esp_log.h"
	#include "freertos/FreeRTOS.h"
	#include "freertos/task.h"
	#include "freertos/queue.h"
	#include "freertos/semphr.h"
	#include "freertos/idf_additions.h" // xTaskCreateWithCaps / vTaskDeleteWithCaps
	#include "esp_heap_caps.h"
	#include "esp_timer.h"
	#include "TimeSync.hpp"
	#include "GoogleServiceAuth.hpp"
	static const char* kTag = "SmtpClient";
	#define PD_TASK_STACK_CAPS (MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT)
#endif

namespace SmtpClient
{

namespace
{
	bool setNonBlocking(int sock, bool nonBlocking)
	{
#if defined _WIN32 || defined _WIN64
		u_long mode = nonBlocking ? 1 : 0;
		return ioctlsocket(sock, FIONBIO, &mode) == 0;
#else
		int flags = fcntl(sock, F_GETFL, 0);
		if (flags < 0) return false;
		flags = nonBlocking ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK);
		return fcntl(sock, F_SETFL, flags) == 0;
#endif
	}
} // namespace

bool SmtpTransport::connectSocket(const std::string& host, uint16_t port, uint32_t timeoutMs, std::string& errOut)
{
#if defined _WIN32 || defined _WIN64
	static bool wsaInit = false;
	if (!wsaInit)
	{
		WSADATA wsa;
		// Safe to call more than once across the process (HttpServer.cpp /
		// UdpServer.cpp do the same); each successful call must be matched by
		// a WSACleanup(), which this deliberately never calls -- same
		// reasoning as those two call sites: the process-lifetime socket
		// layer is never torn down.
		wsaInit = (WSAStartup(MAKEWORD(2, 2), &wsa) == 0);
	}
#endif

	struct addrinfo hints;
	std::memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	struct addrinfo* addrList = nullptr;
	char portStr[8];
	std::snprintf(portStr, sizeof(portStr), "%u", static_cast<unsigned>(port));
	if (getaddrinfo(host.c_str(), portStr, &hints, &addrList) != 0 || addrList == nullptr)
	{
		errOut = "DNS resolution failed for " + host;
		return false;
	}

	bool connected = false;
	int sock = -1;
	for (struct addrinfo* ai = addrList; ai != nullptr && !connected; ai = ai->ai_next)
	{
		sock = static_cast<int>(socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol));
		if (sock < 0) continue;

		setNonBlocking(sock, true);
		int rc = ::connect(sock, ai->ai_addr, static_cast<int>(ai->ai_addrlen));
		if (rc == 0)
		{
			connected = true;
		}
		else
		{
#if defined _WIN32 || defined _WIN64
			bool inProgress = (WSAGetLastError() == WSAEWOULDBLOCK);
#else
			bool inProgress = (errno == EINPROGRESS);
#endif
			if (inProgress)
			{
				fd_set wfds;
				FD_ZERO(&wfds);
				FD_SET(sock, &wfds);
				struct timeval tv;
				tv.tv_sec = static_cast<long>(timeoutMs / 1000);
				tv.tv_usec = static_cast<long>((timeoutMs % 1000) * 1000);
				int sr = select(sock + 1, nullptr, &wfds, nullptr, &tv);
				if (sr > 0)
				{
					int soErr = 0;
					socklen_t len = sizeof(soErr);
					getsockopt(sock, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&soErr), &len);
					connected = (soErr == 0);
				}
			}
		}
		setNonBlocking(sock, false);

		if (!connected)
		{
			PD_SMTP_CLOSESOCK(sock);
			sock = -1;
		}
	}
	freeaddrinfo(addrList);

	if (!connected)
	{
		errOut = "connect to " + host + ":" + portStr + " failed or timed out";
		return false;
	}

	_sock = sock;
	return true;
}

bool SmtpTransport::applyReadTimeout(uint32_t timeoutMs)
{
	int fd = _sock;
#if defined(ESP_PLATFORM) || defined(ESP32)
	if (_tlsActive && _tls != nullptr)
	{
		if (esp_tls_get_conn_sockfd(_tls, &fd) != ESP_OK) return false;
	}
#endif
	if (fd < 0) return false;
#if defined _WIN32 || defined _WIN64
	DWORD tv = timeoutMs;
	return setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv)) == 0;
#else
	struct timeval tv;
	tv.tv_sec = static_cast<long>(timeoutMs / 1000);
	tv.tv_usec = static_cast<long>((timeoutMs % 1000) * 1000);
	return setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == 0;
#endif
}

bool SmtpTransport::writeAll(const char* data, size_t len)
{
	size_t sent = 0;
	while (sent < len)
	{
#if defined(ESP_PLATFORM) || defined(ESP32)
		if (_tlsActive)
		{
			ssize_t n = esp_tls_conn_write(_tls, data + sent, len - sent);
			if (n <= 0)
			{
				// WANT_READ/WANT_WRITE just means "handshake or record layer
				// needs another round trip, no app data moved yet" -- NOT an
				// error. Without the delay this becomes a tight busy-spin on
				// the calling task (the dedicated SMTP worker task, never a
				// SIP thread, but still real CPU/power for nothing) until the
				// peer's next packet arrives.
				if (n == ESP_TLS_ERR_SSL_WANT_READ || n == ESP_TLS_ERR_SSL_WANT_WRITE) { vTaskDelay(1); continue; }
				return false;
			}
			sent += static_cast<size_t>(n);
			continue;
		}
#endif
#if defined _WIN32 || defined _WIN64
		int n = send(_sock, data + sent, static_cast<int>(len - sent), 0);
#else
		ssize_t n = send(_sock, data + sent, len - sent, 0);
#endif
		if (n <= 0) return false;
		sent += static_cast<size_t>(n);
	}
	return true;
}

bool SmtpTransport::readLine(std::string& line, uint32_t timeoutMs)
{
	applyReadTimeout(timeoutMs);
	for (;;)
	{
		size_t nl = _readBuf.find('\n');
		if (nl != std::string::npos)
		{
			std::string raw = _readBuf.substr(0, nl);
			_readBuf.erase(0, nl + 1);
			if (!raw.empty() && raw.back() == '\r') raw.pop_back();
			line = std::move(raw);
			return true;
		}
		// Guard against a line that never terminates -- a misbehaving/hostile
		// server should time out the OVERALL send, not grow this buffer
		// without bound on a device with no virtual memory.
		if (_readBuf.size() > 8192) return false;

		char buf[512];
#if defined(ESP_PLATFORM) || defined(ESP32)
		if (_tlsActive)
		{
			ssize_t n = esp_tls_conn_read(_tls, buf, sizeof(buf));
			if (n <= 0)
			{
				// See the matching comment in writeAll(): WANT_READ/WANT_WRITE
				// is not an error, but spinning on it with no yield would be a
				// busy-wait until the peer's next packet arrives.
				if (n == ESP_TLS_ERR_SSL_WANT_READ || n == ESP_TLS_ERR_SSL_WANT_WRITE) { vTaskDelay(1); continue; }
				return false;
			}
			_readBuf.append(buf, static_cast<size_t>(n));
			continue;
		}
#endif
#if defined _WIN32 || defined _WIN64
		int n = recv(_sock, buf, static_cast<int>(sizeof(buf)), 0);
#else
		ssize_t n = recv(_sock, buf, sizeof(buf), 0);
#endif
		if (n <= 0) return false; // 0 = closed, <0 = error/timeout (SO_RCVTIMEO)
		_readBuf.append(buf, static_cast<size_t>(n));
	}
}

#if defined(ESP_PLATFORM) || defined(ESP32)

bool SmtpTransport::connect(const SmtpDialogue::Config& cfg, bool allowPlain,
                             const std::string& caCertPem, bool insecureSkipVerify,
                             std::string& errOut)
{
	_host = cfg.host;
	_caCertPem = caCertPem;
	_insecureSkipVerify = insecureSkipVerify;

	if (cfg.mode == SmtpDialogue::Mode::Plain && !allowPlain)
	{
		errOut = "plaintext SMTP is disabled (LAN-relay-only opt-in)";
		return false;
	}

	if (cfg.mode == SmtpDialogue::Mode::StartTls)
	{
		// Connect in plaintext; SmtpDialogue::run() upgrades via startTls()
		// once the server has agreed to it.
		return connectSocket(cfg.host, cfg.port, cfg.commandTimeoutMs, errOut);
	}

	if (cfg.mode == SmtpDialogue::Mode::Plain)
	{
		return connectSocket(cfg.host, cfg.port, cfg.commandTimeoutMs, errOut);
	}

	// ImplicitTls: TCP connect + TLS handshake in one blocking call.
	esp_tls_cfg_t tlsCfg;
	std::memset(&tlsCfg, 0, sizeof(tlsCfg));
	tlsCfg.timeout_ms = static_cast<int>(cfg.commandTimeoutMs);
	if (_insecureSkipVerify)
	{
		tlsCfg.skip_common_name = true;
	}
	else if (!_caCertPem.empty())
	{
		tlsCfg.cacert_buf = reinterpret_cast<const unsigned char*>(_caCertPem.c_str());
		tlsCfg.cacert_bytes = static_cast<unsigned int>(_caCertPem.size() + 1); // NUL-terminated PEM
	}
	else
	{
		tlsCfg.crt_bundle_attach = esp_crt_bundle_attach;
	}

	_tls = esp_tls_init();
	if (_tls == nullptr)
	{
		errOut = "esp_tls_init failed";
		return false;
	}
	int rc = esp_tls_conn_new_sync(cfg.host.c_str(), static_cast<int>(cfg.host.size()),
	                                 static_cast<int>(cfg.port), &tlsCfg, _tls);
	if (rc != 1)
	{
		esp_tls_conn_destroy(_tls);
		_tls = nullptr;
		errOut = "TLS connect to " + cfg.host + " failed";
		return false;
	}
	esp_tls_get_conn_sockfd(_tls, &_sock);
	_tlsActive = true;
	return true;
}

bool SmtpTransport::startTls(uint32_t timeoutMs)
{
	if (_sock < 0) return false;

	esp_tls_cfg_t tlsCfg;
	std::memset(&tlsCfg, 0, sizeof(tlsCfg));
	tlsCfg.timeout_ms = static_cast<int>(timeoutMs);
	if (_insecureSkipVerify)
	{
		tlsCfg.skip_common_name = true;
	}
	else if (!_caCertPem.empty())
	{
		tlsCfg.cacert_buf = reinterpret_cast<const unsigned char*>(_caCertPem.c_str());
		tlsCfg.cacert_bytes = static_cast<unsigned int>(_caCertPem.size() + 1);
	}
	else
	{
		tlsCfg.crt_bundle_attach = esp_crt_bundle_attach;
	}

	_tls = esp_tls_init();
	if (_tls == nullptr) return false;
	if (esp_tls_set_conn_sockfd(_tls, _sock) != ESP_OK) { esp_tls_conn_destroy(_tls); _tls = nullptr; return false; }
	if (esp_tls_set_conn_state(_tls, ESP_TLS_CONNECTING) != ESP_OK) { esp_tls_conn_destroy(_tls); _tls = nullptr; return false; }

	int64_t deadline = esp_timer_get_time() + static_cast<int64_t>(timeoutMs) * 1000;
	int rc;
	for (;;)
	{
		rc = esp_tls_conn_new_async(_host.c_str(), static_cast<int>(_host.size()),
		                              0 /* port unused once sockfd is set */, &tlsCfg, _tls);
		if (rc != 0) break; // 1 = done, -1 = failed
		if (esp_timer_get_time() > deadline) { rc = -1; break; }
		vTaskDelay(pdMS_TO_TICKS(10));
	}
	if (rc != 1)
	{
		esp_tls_conn_destroy(_tls);
		_tls = nullptr;
		return false;
	}
	_tlsActive = true;
	return true;
}

void SmtpTransport::close()
{
	if (_tls != nullptr)
	{
		esp_tls_conn_destroy(_tls); // also closes the underlying socket
		_tls = nullptr;
	}
	else if (_sock >= 0)
	{
		PD_SMTP_CLOSESOCK(_sock);
	}
	_sock = -1;
	_tlsActive = false;
}

#else // !ESP_PLATFORM -- host build: plain sockets only, no TLS available.

bool SmtpTransport::connect(const SmtpDialogue::Config& cfg, bool allowPlain,
                             const std::string& /*caCertPem*/, bool /*insecureSkipVerify*/,
                             std::string& errOut)
{
	if (cfg.mode == SmtpDialogue::Mode::Plain && !allowPlain)
	{
		errOut = "plaintext SMTP is disabled (LAN-relay-only opt-in)";
		return false;
	}
	if (cfg.mode == SmtpDialogue::Mode::ImplicitTls)
	{
		// No TLS on the host build (see SmtpClient.hpp's class comment).
		// SmtpDialogue_test.cpp exercises implicit-TLS's *config validation*
		// only; a real handshake is bench-only, per the task's own scope note.
		errOut = "implicit TLS is not available on this build";
		return false;
	}
	// Plain and StartTls both start with an ordinary plaintext connection.
	return connectSocket(cfg.host, cfg.port, cfg.commandTimeoutMs, errOut);
}

bool SmtpTransport::startTls(uint32_t /*timeoutMs*/)
{
	// No TLS on the host build. A STARTTLS-configured send against the fake
	// server in SmtpDialogue_test.cpp therefore always resolves to
	// ResultCode::TlsFailed here -- the same outcome a real server refusing
	// the upgrade would produce, which is itself a case worth covering.
	return false;
}

void SmtpTransport::close()
{
	if (_sock >= 0)
	{
		PD_SMTP_CLOSESOCK(_sock);
		_sock = -1;
	}
	_tlsActive = false;
}

#endif // ESP_PLATFORM

SmtpDialogue::SendResult sendNow(const SmtpDialogue::Config& cfg, const SmtpDialogue::Message& msg,
                                  bool allowPlain, const std::string& caCertPem, bool insecureSkipVerify)
{
	SmtpTransport transport;
	std::string err;
	if (!transport.connect(cfg, allowPlain, caCertPem, insecureSkipVerify, err))
	{
		SmtpDialogue::SendResult res;
		res.code = SmtpDialogue::ResultCode::ConnectFailed;
		res.lastError = err;
		return res;
	}
	return SmtpDialogue::run(transport, cfg, msg);
}

// ---------------------------------------------------------------------
// Bounded single-worker send queue (on-device only -- see SmtpClient.hpp).
// ---------------------------------------------------------------------
#if defined(ESP_PLATFORM) || defined(ESP32)

namespace
{
	constexpr size_t kMaxQueueDepth = 4;

	struct Job
	{
		bool used = false;
		SmtpDialogue::Config cfg;
		SmtpDialogue::Message msg;
		bool allowPlain = false;
		std::string caCertPem;
		bool insecureSkipVerify = false;
		// Snapshotted like everything else in the slot, so the worker owns its
		// own copy of the key material and the caller can return immediately.
		TokenRequest token;
		SmtpDialogue::SendResult result;
		StaticSemaphore_t semBuf;
		SemaphoreHandle_t doneSem = nullptr; // created once, reused for the slot's lifetime
	};

	Job g_jobs[kMaxQueueDepth];
	// Bounded queue of Job* -- the queue storage itself is a fixed array of
	// pointers into g_jobs, never a heap allocation per send.
	QueueHandle_t g_queue = nullptr;
	std::mutex g_slotMutex; // guards Job::used bookkeeping only
	TaskHandle_t g_workerTask = nullptr;

	void workerTaskFn(void*)
	{
		for (;;)
		{
			Job* job = nullptr;
			if (xQueueReceive(g_queue, &job, portMAX_DELAY) != pdTRUE) continue;

			// Fill in Date now that we have TimeSync -- SmtpDialogue itself
			// has no clock (see its header comment).
			job->msg.dateHeader = SmtpDialogue::formatRfc5322Date(timesync::epochSeconds());

			// Mint the XOAUTH2 bearer token HERE, on this task, not on whatever
			// thread called sendAndWait(). This is an RSA-2048 signature plus a
			// full TLS handshake to Google, and this task is the one with the
			// 12 KB PSRAM stack sized for exactly that (see init()). The HTTP
			// handler thread that used to do it inline runs on the 8192-byte
			// IDF pthread default.
			//
			// Cheap on the common path: getAccessToken() serves a cached token
			// until 60 s before expiry, so only the first send of an hour pays
			// the RSA + handshake.
			bool tokenOk = true;
			if (!job->token.serviceAccountEmail.empty() && job->cfg.accessToken.empty())
			{
				std::string tokErr;
				tokenOk = GoogleServiceAuth::getAccessToken(
					job->token.serviceAccountEmail, job->token.subjectUser,
					job->token.scope, job->token.privateKeyPem,
					job->cfg.accessToken, tokErr);
				if (!tokenOk)
				{
					// AuthRejected rather than TransportError: the transport was
					// never reached, the credential is what failed.
					job->result = SmtpDialogue::SendResult{
						SmtpDialogue::ResultCode::AuthRejected, 0,
						"OAuth token fetch failed: " + tokErr};
				}
			}

			if (tokenOk)
			{
				job->result = sendNow(job->cfg, job->msg, job->allowPlain, job->caCertPem, job->insecureSkipVerify);
			}

			if (job->result.ok())
			{
				ESP_LOGI(kTag, "send to <%s> ok", job->msg.to.c_str());
			}
			else
			{
				ESP_LOGW(kTag, "send to <%s> failed: code=%d smtp=%d err=%s",
				         job->msg.to.c_str(), static_cast<int>(job->result.code),
				         job->result.smtpReplyCode, job->result.lastError.c_str());
			}

			// Drop the secrets this slot was carrying before releasing it.
			//
			// g_jobs is a static array that lives for the whole process, so
			// anything left in a slot stays resident until that slot happens to
			// be reused -- possibly never. The App Password was already living
			// there; this change adds the service account's RSA PRIVATE KEY,
			// which is a materially stronger secret, so it should not be the
			// thing that quietly extends that pattern.
			//
			// Overwrite-then-clear rather than just clear(): clear() only sets
			// the length, leaving the bytes in the buffer. Honest caveat -- this
			// is best-effort, not a guaranteed erase: for a short string the data
			// sits in the small-string buffer, and any earlier reallocation may
			// have left a copy elsewhere on the heap. It shrinks the window and
			// removes the steady-state copy, which is worth having; it is not a
			// claim that the key is unrecoverable from RAM.
			auto scrub = [](std::string& v) {
				if (!v.empty()) { v.assign(v.size(), '\0'); }
				v.clear();
			};
			scrub(job->token.privateKeyPem);
			scrub(job->cfg.password);
			scrub(job->cfg.accessToken);

			xSemaphoreGive(job->doneSem);
			{
				std::lock_guard<std::mutex> lk(g_slotMutex);
				job->used = false;
			}
		}
	}
} // namespace

void init()
{
	if (g_queue != nullptr) return; // already initialised

	for (auto& j : g_jobs)
	{
		j.doneSem = xSemaphoreCreateBinaryStatic(&j.semBuf);
	}

	g_queue = xQueueCreate(kMaxQueueDepth, sizeof(Job*));
	if (g_queue == nullptr)
	{
		ESP_LOGE(kTag, "xQueueCreate failed -- email sending disabled");
		return;
	}

	// One persistent worker, not one task per send: the queue already
	// enforces "single in-flight", so there is no need to pay task
	// creation/teardown cost on every message. Socket + TLS I/O only, never
	// an NVS/flash write itself (the caller snapshots cfg/msg into the slot
	// before this task ever sees them) -- safe for a PSRAM-backed stack per
	// PsramTask.hpp's rule. 12 KB matches the other "transient TLS worker"
	// tasks that file documents (a crt-bundle handshake plus the streaming
	// DATA writer wants the headroom).
	BaseType_t created = xTaskCreateWithCaps(workerTaskFn, "smtp_worker", 12288, nullptr,
	                                          4, &g_workerTask, PD_TASK_STACK_CAPS);
	if (created != pdPASS)
	{
		ESP_LOGE(kTag, "xTaskCreateWithCaps failed -- email sending disabled");
		g_workerTask = nullptr;
	}
}

bool sendAndWait(const SmtpDialogue::Config& cfg, const SmtpDialogue::Message& msg,
                  bool allowPlain, const std::string& caCertPem, bool insecureSkipVerify,
                  uint32_t waitMs, SmtpDialogue::SendResult& result,
                  const TokenRequest& token)
{
	if (g_queue == nullptr)
	{
		result.code = SmtpDialogue::ResultCode::TransportError;
		result.lastError = "email sending is not initialised";
		return false;
	}

	Job* slot = nullptr;
	{
		std::lock_guard<std::mutex> lk(g_slotMutex);
		for (auto& j : g_jobs)
		{
			if (!j.used) { j.used = true; slot = &j; break; }
		}
	}
	if (slot == nullptr)
	{
		result.code = SmtpDialogue::ResultCode::TransportError;
		result.lastError = "send queue full -- try again shortly";
		return false;
	}

	// Drain any stale "give" left over from a previous occupant of this slot
	// that timed out below without the worker having caught up yet -- see
	// SmtpClient.hpp's sendAndWait doc comment. The semaphore itself outlives
	// every individual call (created once in init()), so this is the only
	// place that needs to reason about reuse.
	xSemaphoreTake(slot->doneSem, 0);

	slot->cfg = cfg;
	slot->msg = msg;
	slot->allowPlain = allowPlain;
	slot->caCertPem = caCertPem;
	slot->insecureSkipVerify = insecureSkipVerify;
	slot->token = token;

	if (xQueueSend(g_queue, &slot, 0) != pdTRUE)
	{
		std::lock_guard<std::mutex> lk(g_slotMutex);
		slot->used = false;
		result.code = SmtpDialogue::ResultCode::TransportError;
		result.lastError = "send queue full -- try again shortly";
		return false;
	}

	if (xSemaphoreTake(slot->doneSem, pdMS_TO_TICKS(waitMs)) != pdTRUE)
	{
		// The worker may still be mid-send; it owns clearing `used` and will
		// do so on its own once it finishes (see workerTaskFn) -- nothing
		// here reaches into the slot again.
		result.code = SmtpDialogue::ResultCode::Timeout;
		result.lastError = "send did not complete within the wait budget";
		return false;
	}

	result = slot->result;
	return true;
}

#else // !ESP_PLATFORM -- host build: no FreeRTOS queue to demonstrate. There
      // is exactly one caller (the test process), so sendAndWait's whole job
      // -- keeping a second concurrent sender from touching the network
      // directly -- has nothing to arbitrate; it calls sendNow() in place.

void init() {}

bool sendAndWait(const SmtpDialogue::Config& cfg, const SmtpDialogue::Message& msg,
                  bool allowPlain, const std::string& caCertPem, bool insecureSkipVerify,
                  uint32_t /*waitMs*/, SmtpDialogue::SendResult& result,
                  const TokenRequest& token)
{
	// Minting a bearer token needs GoogleServiceAuth::getAccessToken(), which is
	// device-only (real network + cJSON). Refusing HERE rather than in the HTTP
	// handler keeps the "device-only" knowledge in one place and means every
	// caller gets the same answer -- the handler used to carry its own #else arm
	// saying this, which would have drifted the moment a second caller appeared.
	if (!token.serviceAccountEmail.empty() && cfg.accessToken.empty())
	{
		result = SmtpDialogue::SendResult{
			SmtpDialogue::ResultCode::AuthRejected, 0,
			"XOAUTH2 token fetch is device-only -- not available on this build"};
		return false;
	}
	result = sendNow(cfg, msg, allowPlain, caCertPem, insecureSkipVerify);
	return true;
}

#endif // ESP_PLATFORM

} // namespace SmtpClient
