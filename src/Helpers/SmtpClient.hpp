#ifndef SMTP_CLIENT_HPP
#define SMTP_CLIENT_HPP

// SmtpClient: the real network transport for SmtpDialogue, plus (on-device)
// the bounded single-worker send queue that keeps every TLS handshake and
// blocking socket call off the SIP threads.
//
// SmtpTransport is ONE class, not "an ESP implementation and a host stub":
// plain-TCP connect/read/write are ordinary BSD/Winsock sockets on BOTH
// platforms (same cross-platform #if as HttpServer.hpp), so the host test
// suite drives the REAL transport -- not a fake -- against a real loopback
// fake-SMTP-server socket. Only implicit-TLS connect and the STARTTLS
// upgrade are `#if defined(ESP_PLATFORM)`; calling either on a host build
// fails cleanly (ConnectFailed / startTls() returns false) rather than being
// unavailable, which is itself an exercised path in
// SmtpDialogue_test.cpp (a STARTTLS negotiation the transport cannot
// complete looks the same on host as a server that refused the upgrade).
//
// See docs/SETUP_GUIDE.md / docs/API.md for the /setup/email + /api/email*
// surface that calls into this; see EmailConfigStore.hpp for where Config
// comes from and GoogleServiceAuth.hpp for how cfg.accessToken gets filled
// in for XOAuth2.

#include "SmtpDialogue.hpp"

#include <cstdint>
#include <string>

#if defined(__linux__) || defined(ESP_PLATFORM)
#include <sys/socket.h>
#elif defined _WIN32 || defined _WIN64
#include <WinSock2.h>
#endif

#if defined(ESP_PLATFORM) || defined(ESP32)
#include "esp_tls.h"
#endif

namespace SmtpClient
{

// Real transport: plain sockets everywhere, esp_tls for anything encrypted.
class SmtpTransport : public SmtpDialogue::Transport
{
public:
	SmtpTransport() = default;
	~SmtpTransport() override { close(); }
	SmtpTransport(const SmtpTransport&) = delete;
	SmtpTransport& operator=(const SmtpTransport&) = delete;

	// Establishes the connection per cfg.mode:
	//   Plain / ImplicitTls -- fully connected (and, for ImplicitTls,
	//     handshaked) by the time this returns true. Plain is refused unless
	//     `allowPlain` is true (the caller enforces the "opt-in, LAN relay
	//     only" rule from EmailConfigStore, not this class).
	//   StartTls -- connects in plaintext only; SmtpDialogue::run() calls
	//     startTls() itself after the server's "220" to the STARTTLS command.
	// `caCertPem`/`insecureSkipVerify` are ESP-only (ignored on host, which
	// has no TLS at all): empty caCertPem means the esp_crt_bundle default.
	bool connect(const SmtpDialogue::Config& cfg, bool allowPlain,
	             const std::string& caCertPem, bool insecureSkipVerify,
	             std::string& errOut);

	bool writeAll(const char* data, size_t len) override;
	bool readLine(std::string& line, uint32_t timeoutMs) override;
	bool startTls(uint32_t timeoutMs) override;
	void close();

private:
	bool connectSocket(const std::string& host, uint16_t port, uint32_t timeoutMs, std::string& errOut);
	bool applyReadTimeout(uint32_t timeoutMs);

	int _sock = -1;
	std::string _readBuf; // bytes read but not yet consumed as a full line
	bool _tlsActive = false;

#if defined(ESP_PLATFORM) || defined(ESP32)
	esp_tls_t* _tls = nullptr;
	std::string _host;           // retained for startTls()'s SNI/hostname arg
	std::string _caCertPem;      // retained buffer -- esp_tls_cfg_t just points at it
	bool _insecureSkipVerify = false;
#endif
};

// Runs one send to completion, synchronously, on whatever thread/task calls
// it. This is the one code path that actually touches the network -- both
// the on-device worker task (below) and, on host, the test suite's direct
// calls funnel through here.
SmtpDialogue::SendResult sendNow(const SmtpDialogue::Config& cfg, const SmtpDialogue::Message& msg,
                                  bool allowPlain, const std::string& caCertPem, bool insecureSkipVerify);

// Starts the bounded single-worker send task. On-device this creates the
// FreeRTOS queue/task (PSRAM-backed stack, PsramTask.hpp) that sendAndWait()
// dispatches through; on host there is no FreeRTOS to create it on, so this
// is a no-op and sendAndWait() below calls sendNow() directly instead (both
// the SipServer host binary and the gtest suite link this file, so "the one
// caller" language is about there being no queue to arbitrate, not about
// which host target calls it). Safe to call more than once.
void init();

// Runs a send through the same admission path production traffic uses: one
// in-flight TLS session at a time, serviced by the dedicated worker task, so
// the caller's own thread never does socket/TLS I/O itself. Blocks the
// CALLING thread (never a SIP thread -- see call sites: the HTTP
// per-connection thread and the dashboard terminal's request handler) for up
// to `waitMs`. Returns false (result.code = TransportError, "send queue
// full") without touching the network if all queue slots are already busy;
// returns false (result.code = Timeout) if the worker has not finished
// within `waitMs` -- in that case the send may still complete in the
// background; the slot frees itself once it does.
// The service-account material needed to MINT an XOAUTH2 bearer token, for the
// Workspace path where the caller has no token yet.
//
// This exists so the minting happens on the WORKER, not on the caller's thread.
// Fetching a token is not a lightweight lookup: it is an RSA-2048
// mbedtls_pk_sign plus a full TLS handshake to oauth2.googleapis.com. Doing it
// inline in an HTTP handler put roughly a second of RSA and a TLS session on an
// IDF pthread running the 8192-byte CONFIG_PTHREAD_TASK_STACK_SIZE_DEFAULT,
// while every other TLS-handshake path in this codebase deliberately gets a
// dedicated 12 KB PSRAM-backed stack (PsramTask.hpp). That is the same
// unmeasured-stack-budget mistake the RFC 4733 drain had, and the same reason
// sendAndWait()'s own contract below promises the caller's thread never does
// socket/TLS I/O itself -- a promise the inline fetch quietly broke.
//
// Leave serviceAccountEmail empty for "nothing to mint": the App Password path
// and any caller that already has a token in cfg.accessToken.
struct TokenRequest
{
	std::string serviceAccountEmail;
	std::string subjectUser;    // the mailbox being impersonated
	std::string scope;          // e.g. "https://mail.google.com/"
	std::string privateKeyPem;
};

bool sendAndWait(const SmtpDialogue::Config& cfg, const SmtpDialogue::Message& msg,
                  bool allowPlain, const std::string& caCertPem, bool insecureSkipVerify,
                  uint32_t waitMs, SmtpDialogue::SendResult& result,
                  const TokenRequest& token = {});

} // namespace SmtpClient

#endif
