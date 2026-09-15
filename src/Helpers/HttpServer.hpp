#ifndef HTTP_SERVER_HPP
#define HTTP_SERVER_HPP

#if defined(__linux__) || defined(ESP_PLATFORM)
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#elif defined _WIN32 || defined _WIN64
#include <WinSock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#endif

#include <string>
#include <functional>
#include <atomic>
#include <thread>
#include <cstdint>

#include "AdminAuth.hpp"   // AdminAuth::Role, used by requireAdmin()'s minRole param

// Forward declaration — the HttpServer queries the SIP engine via this
class RequestsHandler;

class HttpServer
{
public:
	HttpServer(const std::string& ip, int port, RequestsHandler* handler = nullptr);
	~HttpServer();

	void start();

	// Late-bind the live SIP registrar. The dashboard must be able to start
	// BEFORE the SIP stack exists — an unprovisioned device holds SIP dark
	// until an admin credential is committed *via this web UI*, so HttpServer
	// cannot wait for the handler (that ordering deadlocks onboarding on the
	// headless eth/wifi builds). All endpoints null-check, so until this is
	// called they serve empty datasets. Same idiom as SshServer::attachHandler.
	void attachHandler(RequestsHandler* h)
	{
		_handler.store(h, std::memory_order_release);
	}

	// Issue #35: true iff `path` has the shape "/config/<12 lowercase hex>.cfg"
	// — a phone's zero-touch auto-provisioning fetch. Pure string-shape check;
	// doesn't touch the registry (sendConfigCfg does that). Public/static so
	// it's host-testable on its own (see tests/ProvisioningConfig_test.cpp).
	static bool isProvisioningConfigPath(const std::string& path);

private:
	// Idempotent socket lifecycle, called only from this class's own thread
	// (the constructor, or acceptLoop() once running) — never from another
	// thread, so _listenSock needs no separate lock.
	bool openListenSocket();                    // no-op + true if already open
	void closeListenSocket();                   // no-op if already closed; used
	                                             // only by the destructor to unblock
	                                             // accept() during teardown.

	void acceptLoop();
	void handleClient(int clientSock);

	// HTTP request parsing
	struct HttpRequest {
		std::string method;
		std::string path;
		std::string body;
		std::string origin;  // value of the Origin: header, if present
		std::string host;    // value of the Host: header, if present
		std::string cookie;  // value of the Cookie: header, if present
		std::string csrf;    // value of the X-CSRF: header, if present
		// Peer address, filled from getpeername() in handleClient(). Used only as
		// the brute-force accounting key for /api/admin/login, never for authz:
		// a source address is trivially spoofable on the shared link (see
		// docs/THREAT_MODEL.md), so it buys fairness between clients, not trust.
		std::string clientIp;
	};
	HttpRequest parseRequest(const std::string& raw);

	// The single admission gate for every non-public endpoint. Replaces the
	// same-origin/auth block that used to be copy-pasted at each route — two
	// endpoints had already been missed that way (/api/configuring had no gate
	// at all; /api/pcap, /api/trace and /api/diagnostics/pcap had no same-origin
	// check despite serving raw SIP bytes including Authorization digests).
	//
	// Returns true if the handler may run. On false it has ALREADY written the
	// error response, so the caller must not write another.
	//
	// `needCsrf` should be true for every mutating request and false for reads;
	// the token is only checked when a session actually exists to bind it to.
	// `minRole` (issue #173) gates the THREE owner-only actions (factory reset,
	// config export WITH the encrypted secrets block, OTA upload) — pass
	// AdminAuth::Role::Owner for those three call sites only; every other call
	// site keeps the default (Sysop), unchanged. See AdminAuth::
	// sessionSatisfiesRole() for the no-owner-yet fallback this relies on.
	bool requireAdmin(int sock, const HttpRequest& req, bool needCsrf,
		AdminAuth::Role minRole = AdminAuth::Role::Sysop);
	// Answers "is this caller logged in?" WITHOUT answering the request, for
	// endpoints that serve everyone but disclose more to a session (#207).
	bool hasValidAdminSession(const HttpRequest& req) const;

	// Same-origin check only, for the pre-session endpoints (login, logout).
	// Same contract: on false the response has already been written.
	bool requireSameOrigin(int sock, const HttpRequest& req);

	// The pd_session cookie value, or "" if absent.
	std::string sessionToken(const HttpRequest& req) const;

	// Response builders
	void sendResponse(int sock, int statusCode, const std::string& statusText,
	                   const std::string& contentType, const std::string& body);
	// Same as sendResponse, but injects an extra raw header line (e.g.
	// "Set-Cookie: pd_session=...; HttpOnly; Path=/; SameSite=Strict"). The
	// extraHeader must NOT include the trailing CRLF.
	void sendResponseWithHeader(int sock, int statusCode, const std::string& statusText,
	                   const std::string& contentType, const std::string& body,
	                   const std::string& extraHeader);
	void sendRedirect(int sock, const std::string& location);
	// Takes the request so the rendered page can carry this session's CSRF token.
	void sendHtml(int sock, const HttpRequest& req);
	// `authenticated` controls DISCLOSURE, not access: the endpoint always answers
	// (the dashboard needs it to render the login form) but withholds the
	// extension roster from an unauthenticated caller (#207).
	void sendApiStatus(int sock, bool authenticated);
	// Issue #184: GET /metrics — Prometheus text-exposition format over the same
	// thread-safe getters /api/status already reads. Intentionally ungated (the
	// full reasoning, including why a gated scrape endpoint would be a dead one,
	// is at sendApiMetrics's definition in the .cpp).
	void sendApiMetrics(int sock);
	// SoftAP security (docs/THREAT_MODEL.md §6 / FEATURE_ROADMAP P0): report and
	// toggle WPA2 on the standalone AP, and show/rotate its passphrase. Turning
	// it on is a breaking change for already-associated phones, so it is an
	// explicit operator action rather than a default.
	void sendApiApSecurity(int sock);
	void sendApiApSecuritySet(int sock, const std::string& body);

	// SIP registrar admission mode + the Learn-mode adopted-extension roster.
	// Until these landed, RequestsHandler::setRegistrarMode() was called from unit
	// tests ONLY: digest authentication was fully implemented and fully unreachable
	// on a shipped device, because nothing in production ever wrote the persisted
	// mode. These endpoints (and the flash-time seed) are what make it operable.
	void sendApiRegistrar(int sock);
	void sendApiRegistrarSet(int sock, const std::string& body);
	void sendApiRegistrarDevice(int sock, const std::string& body);
	void sendApiKill(int sock, const std::string& body);
	// Phase 2: read-only Call Detail Records (newest first). Ungated like /api/status.
	void sendApiCdr(int sock);
	// Issue #33: downloads the last POCKETDIAL_PCAP_RING_SIZE SIP signaling
	// packets as a .pcap. Session-gated by the caller in handleClient() (see the
	// dispatch entry) — unlike /api/cdr, this carries full message bytes
	// (Contact URIs, User-Agent, Authorization digests), not just call metadata.
	void sendApiPcap(int sock);
	// Issue #32: the same capture ring as JSON, for the dashboard's polling live
	// tracer. Session-gated by the caller, same as sendApiPcap.
	void sendApiTrace(int sock);

	// Serves the Yealink auto-provisioning config for an adopted device's MAC
	// (already validated by isProvisioningConfigPath). 404 if the MAC isn't in
	// the adopted-device registry — same response whether it's a genuinely
	// unknown MAC or one that just isn't provisioned yet, so a prober can't
	// tell the difference.
	void sendConfigCfg(int sock, const std::string& mac);
	// Phase 2: set per-extension Do Not Disturb. Mutating (same-origin + auth gated).
	void sendApiDnd(int sock, const std::string& body);
	// Class A sweep: set per-extension call forwarding (always/busy/noanswer) and
	// configure ring/hunt groups. Mutating (same-origin + auth gated), mirroring DND.
	void sendApiForward(int sock, const std::string& body);
	void sendApiGroup(int sock, const std::string& body);
	// Issue #69: upsert/delete one dial-plan rule. Same gate and same shape as
	// sendApiGroup — validation lives in RequestsHandler::setDialRule; this only
	// rejects the parameter-level mistakes it can name precisely (missing pattern,
	// bad action) so the operator gets a 400 instead of a silent server-side drop.
	void sendApiDialPlan(int sock, const std::string& body);
	// Telephony-API credential slots (ported from drawbridge). GET lists all
	// kSlots display-safe views (secrets masked); PUT sets one slot's fields
	// (an empty secret means "keep existing" -- TelephonyApiConfig::setSlot's
	// keepSecret contract); activate marks a slot as the boot-time provider
	// source. Same same-origin+auth gate as the other mutating PBX endpoints
	// above (POST for activate since it has no body to speak of, mirroring
	// sendApiKill's shape).
	void sendApiTelephonyConfigList(int sock);
	void sendApiTelephonyConfigSet(int sock, size_t slotIdx, const std::string& body);
	void sendApiTelephonyConfigActivate(int sock, size_t slotIdx);
	void sendApiTelephonyConfigTest(int sock, size_t slotIdx);
	void sendApiTelephonyConfigDelete(int sock, size_t slotIdx);
	// DID -> extension inbound routing (new). GET lists all configured
	// mappings; PUT adds/updates one (extension validated against the same
	// dial-token charset + reserved-virtual-extension set sendApiDialPlan/
	// PbxFeatureConfig already enforce, not a new rule); DELETE removes one
	// (idempotent, per DidMapping::removeMapping's contract).
	void sendApiDidMappingList(int sock);
	// Issue #166 (Kari's Law): who gets alerted when 911 is dialed.
	void sendApiE911Get(int sock);
	void sendApiE911Set(int sock, const std::string& body);
	void sendApiDidMappingSet(int sock, const std::string& body);
	void sendApiDidMappingDelete(int sock, const std::string& body);
	void sendApiWifiScan(int sock);
	void sendApiWifiConnect(int sock, const std::string& body);
	void sendApiWifiModeAp(int sock);
	void sendApiConfiguring(int sock);
	void sendApiFactoryReset(int sock, const std::string& body);
	void send404(int sock);

	// --- Admin auth endpoints (PIN-gated session layer; see AdminAuth.hpp) ---
	void sendApiAdminStatus(int sock, const HttpRequest& req);
	void sendApiAdminSetCredential(int sock, const HttpRequest& req);
	// Issue #173: bootstrap/replace the OWNER principal. Dispatched with
	// requireAdmin(..., minRole=Owner) — which, via sessionSatisfiesRole()'s
	// no-owner-yet fallback, lets a sysop session bootstrap the FIRST owner
	// account but requires an existing owner to replace one.
	void sendApiAdminSetOwnerCredential(int sock, const HttpRequest& req);
	void sendApiAdminLogin(int sock, const HttpRequest& req);
	void sendApiAdminLogout(int sock, const HttpRequest& req);

	// --- Config export/import (issue #186) ---
	// GET/POST /api/config/export. `withSecrets`/`password` select the
	// password-gated "secretsEnc" block; the dispatch site in handleClient()
	// decides withSecrets from whether a `password` form field was sent (POST
	// only — the plain GET never carries one) and requires Owner only on the
	// withSecrets path (see requireAdmin's minRole).
	void sendApiConfigExport(int sock, bool withSecrets, const std::string& password);
	// POST /api/config/import. Body is form-encoded: blob=<url-encoded JSON
	// export>&password=<optional>&confirm=REPLACE. Sysop-level (default
	// minRole) with its own confirm-before-overwrite interlock, per #173's
	// "sysop gets add/change with a confirm-before-overwrite interlock" —
	// restoring secrets is not one of the three owner-only ACTIONS #173 names.
	void sendApiConfigImport(int sock, const std::string& body);

	// Music-on-hold panel (PBX settings). Status reports the BUILD capability and
	// the runtime state separately, so a client can tell "no card on this board"
	// from "no clip uploaded yet". Preview rings an extension and streams the clip
	// to it, which is how an operator checks a clip without parking a real call.
	void sendApiSyslogStatus(int sock);
	void sendApiSyslogSet(int sock, const std::string& body);

	// Issue #159 (SMTP client): GET never echoes the stored secret/private
	// key -- only hasPassword/hasGsaKey booleans (see EmailConfigStore.hpp's
	// top comment and EmailHttp_test.cpp's "never echoes secrets, even
	// authenticated" case). POST's `pass`/`gsaKey` form fields keep the
	// existing stored value when submitted empty. Test sends synchronously
	// through SmtpClient::sendAndWait() (the same bounded single-worker
	// queue a real voicemail-to-email send would use) and reports the
	// structured result inline -- this IS the "Send test message" button and
	// the `email test <addr>` terminal command's only backend.
	void sendApiEmailConfig(int sock);
	void sendApiEmailConfigSet(int sock, const std::string& body);
	void sendApiEmailTest(int sock, const std::string& body);
	// GET /setup/email's standalone page (PD_HTML_8 -- NOT part of the "/"
	// SPA's CGA_INDEX_HTML_PARTS assembly). Ungated like sendHtml(), for the
	// same reason: the shell alone discloses nothing, and the dashboard's own
	// convention is that only the DATA endpoints are session-gated (see
	// docs/THREAT_MODEL.md §4 E-2).
	void sendEmailSetupHtml(int sock, const HttpRequest& req);

	void sendApiMohStatus(int sock);
	void sendApiMohPreview(int sock, const std::string& body);
	void sendApiMohPreviewStop(int sock);

	// Streams an uploaded music-on-hold clip to /sdcard/moh.wav and reloads it.
	// Takes the same streaming treatment as the OTA image and for the same reason:
	// ~800 KB of audio must not go through the 16 KB buffered path. Writes to a
	// temporary name and renames on success, so a failed upload cannot leave a
	// half-written file that looks valid enough to loop a fragment. Replies 501 on
	// a build with no card. Admin + CSRF gated at the dispatch site.
	void handleMohUpload(int sock, const std::string& alreadyRead,
	                     size_t bodyStart, size_t contentLength);

	// --- OTA firmware-update endpoints (see OtaUpdater.hpp + docs/OTA.md) ---
	// Streams the request body straight into the inactive OTA slot. This MUST
	// bypass the 16 KB buffered path in handleClient(); see handleOtaUpload().
	// On host this is a stub that drains the body and replies 501.
	// `headerBytesRead` is the already-recv'd buffer (request line + headers and
	// possibly the first body bytes); `contentLength` is the parsed body size.
	void handleOtaUpload(int sock, const std::string& alreadyRead,
	                     size_t bodyStart, size_t contentLength);
	// Read-only JSON: running / boot / next partition, pending flag, last error.
	void sendApiOtaStatus(int sock);
	// Reboots into a staged image (device) or simulates it (host).
	void sendApiOtaReboot(int sock);

	// Streaming helper for the OTA upload: drains exactly `contentLength` bytes
	// from `sock`, feeding `chunkSink(ptr, len)` for each chunk. `prefix`/
	// `prefixLen` are body bytes already present in the initial header recv.
	// Returns true iff the full body was consumed. Used so the same draining
	// logic backs both the device write path and the host discard path.
	bool streamBody(int sock, const char* prefix, size_t prefixLen,
	                size_t contentLength,
	                const std::function<bool(const uint8_t*, size_t)>& chunkSink);

	// Returns true if the request has no Origin header (direct browser nav / curl)
	// or if the Origin host matches the Host header (same-origin). Blocks CSRF from
	// third-party pages on the same AP.
	bool isSameOrigin(const HttpRequest& req) const;

	// Extract the value of a named cookie (e.g. "pd_session") from the request's
	// Cookie header, or "" if absent.
	static std::string cookieValue(const HttpRequest& req, const std::string& name);

	// True iff the request carries a valid (live) pd_session cookie. Used to gate
	// the state-changing endpoints once a PIN has been provisioned.
	bool isAuthed(const HttpRequest& req) const;

	// Close a client socket portably
	void closeSocket(int sock);

	std::string _ip;
	int _port;
	int _listenSock;
	// Written by attachHandler() from the SIP task once the registrar exists;
	// read by the HTTP accept/worker threads. nullptr until then.
	std::atomic<RequestsHandler*> _handler;
	std::atomic<bool> _running;
	std::thread _acceptThread;

	// Track server uptime
	uint64_t _startTime;
	uint64_t currentTimeMs() const;
};

#endif
