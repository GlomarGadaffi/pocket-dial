#include "TelephonyAnchorClient.hpp"

#if !defined(ESP_PLATFORM) && !defined(ESP32)

// ── Host stubs: compile-compatible no-ops for host tests ──────────────────
TelephonyAnchorClient::TelephonyAnchorClient() = default;
TelephonyAnchorClient::~TelephonyAnchorClient() = default;

bool TelephonyAnchorClient::init(const std::string&, const std::string&, const std::string&, const std::string&)
{
	return false;
}

bool TelephonyAnchorClient::start()
{
	return false;
}

void TelephonyAnchorClient::stop()
{
}

bool TelephonyAnchorClient::isConnected() const
{
	return false;
}

bool TelephonyAnchorClient::isStreaming() const
{
	return false;
}

bool TelephonyAnchorClient::makeCall(const std::string&, std::string*)
{
	return false;
}

bool TelephonyAnchorClient::answerCall(const std::string&)
{
	return false;
}

bool TelephonyAnchorClient::dropCall(const std::string&)
{
	return false;
}

void TelephonyAnchorClient::setEventCallback(EventCallback)
{
}

bool TelephonyAnchorClient::writeAudio(std::string_view, const int16_t*, size_t)
{
	return false;
}

void TelephonyAnchorClient::registerAudioRxCallback(AudioRxCallback)
{
}

void TelephonyAnchorClient::tick()
{
}

void TelephonyAnchorClient::setRewarmIntervalSec(uint32_t)
{
}

#else

// ── ESP-IDF Implementation: real mTLS, WSS and chunked HTTPS streams ─────────
#include "esp_log.h"
#include "lwip/sockets.h"
#include "cJSON.h"
#include "UrlEncode.hpp"
#include "JsonEscape.hpp"
#include <sstream>
#include <cstring>
#include <cstdio>
#include <vector>
#include <cstdint>
#include "esp_crt_bundle.h"
#include "esp_timer.h"
#include "mbedtls/base64.h"
#include "TelephonyAnchorLogic.hpp"   // host-tested entity-path tokenizer + URL builders (issue #49)
#include "PsramTask.hpp"            // #100: PSRAM-backed task stacks (off the scarce internal-RAM heap)

static const char* TAG = "TelephonyAnchor";

// RAII guard: cJSON_Delete on scope exit. Shared by the WS event parser and the
// live-state reconcile/device GET helpers so every parse path frees on every return.
namespace {
struct CJsonDeleter
{
	cJSON* r;
	~CJsonDeleter() { if (r) cJSON_Delete(r); }
};
} // namespace

// Telephony Call Control WS event_type is a NUMERIC enum, not a string. From the Telephony
// call-control-examples (server/src/types.ts):
//   enum EventType { Upset, Remove, DTMFstring, PromptPlaybackFinished }
// TypeScript auto-numbers these 0..3. The earlier parser compared event_type to
// the strings "Upset"/"Remove"/"DTMFstring", but cJSON gives a number there
// (valuestring == NULL), so every event was silently dropped — the device never
// saw a call answer, so it never sent 200 OK / started media / dropped the leg.
enum TelephonyEventType {
	TEL_EV_UPSET       = 0,
	TEL_EV_REMOVE      = 1,
	TEL_EV_DTMF        = 2,
	TEL_EV_PROMPT_DONE = 3,
};

// Fallback token lifetime when the JWT can't be decoded: 50 minutes. This is
// deliberately the JWT's real ~1h validity minus margin, NOT the OAuth
// expires_in (Telephony reports 60s there, which is wrong and would cause a refresh
// storm that kills the active media streams).
static constexpr int64_t kTokenFallbackLifetimeUs = 50LL * 60 * 1000000;

// Decode a JWT's declared lifetime (exp - iat) in microseconds from its payload
// segment. Returns kTokenFallbackLifetimeUs if anything about the token is
// unparseable. Uses the JWT's own claims so no wall-clock/SNTP is required —
// the result is compared against the monotonic esp_timer.
static int64_t decodeJwtLifetimeUs(const std::string& jwt)
{
	size_t firstDot = jwt.find('.');
	if (firstDot == std::string::npos) return kTokenFallbackLifetimeUs;
	size_t secondDot = jwt.find('.', firstDot + 1);
	if (secondDot == std::string::npos) return kTokenFallbackLifetimeUs;

	std::string payload = jwt.substr(firstDot + 1, secondDot - firstDot - 1);
	if (payload.empty()) return kTokenFallbackLifetimeUs;

	// base64url -> base64, then pad to a multiple of 4.
	for (char& c : payload)
	{
		if (c == '-') c = '+';
		else if (c == '_') c = '/';
	}
	while (payload.size() % 4 != 0) payload.push_back('=');

	std::vector<unsigned char> decoded(payload.size()); // decoded is always smaller
	size_t outLen = 0;
	int rc = mbedtls_base64_decode(decoded.data(), decoded.size(), &outLen,
	                               reinterpret_cast<const unsigned char*>(payload.data()),
	                               payload.size());
	if (rc != 0 || outLen == 0) return kTokenFallbackLifetimeUs;

	std::string json(reinterpret_cast<char*>(decoded.data()), outLen);
	cJSON* root = cJSON_Parse(json.c_str());
	if (!root) return kTokenFallbackLifetimeUs;

	int64_t lifetimeUs = kTokenFallbackLifetimeUs;
	cJSON* exp = cJSON_GetObjectItem(root, "exp");
	cJSON* iat = cJSON_GetObjectItem(root, "iat");
	if (cJSON_IsNumber(exp) && cJSON_IsNumber(iat))
	{
		double span = exp->valuedouble - iat->valuedouble; // seconds
		if (span > 0 && span < 86400) // sanity: positive, under a day
		{
			lifetimeUs = static_cast<int64_t>(span * 1000000.0);
		}
	}
	cJSON_Delete(root);
	return lifetimeUs;
}

TelephonyAnchorClient::TelephonyAnchorClient() = default;

TelephonyAnchorClient::~TelephonyAnchorClient()
{
	shutdownImpl();   // non-virtual: never dispatch a virtual call from a destructor
	// #100: free each slot's done-sem (a raw FreeRTOS handle — CallSlot's dtor won't reclaim it).
	for (auto& s : _calls)
	{
		if (s.rxDoneSem)
		{
			vSemaphoreDelete(s.rxDoneSem);
			s.rxDoneSem = nullptr;
		}
	}
}

bool TelephonyAnchorClient::init(const std::string& baseUrl,
                               const std::string& clientId,
                               const std::string& clientSecret,
                               const std::string& sourceDn)
{
	std::lock_guard<std::mutex> lock(_mutex);
	_baseUrl      = baseUrl;
	_clientId     = clientId;
	_clientSecret = clientSecret;
	_sourceDn     = sourceDn;
	return true;
}

bool TelephonyAnchorClient::start()
{
	{
		std::lock_guard<std::mutex> lock(_mutex);
		if (_running)
		{
			return false;
		}
		_running = true;
	}

	// 1. Fetch OAuth token
	if (!fetchToken())
	{
		ESP_LOGE(TAG, "Failed to retrieve OAuth token");
		std::lock_guard<std::mutex> lock(_mutex);
		_running = false;
		return false;
	}

	// 2. Connect to control WebSocket
	if (!connectWs())
	{
		ESP_LOGE(TAG, "Failed to connect control WebSocket");
		std::lock_guard<std::mutex> lock(_mutex);
		_running = false;
		return false;
	}

	// 2b. Spin up the WS event worker pool (#43) so handleWsEvent can hand off the blocking
	// status-check / media-start and keep the WS task answering PINGs.
	startWsWorkers();

	// 3. Pre-establish the control-plane TLS session so the first makecall
	// doesn't pay the handshake during post-dial delay.
	warmCtrlConnection();
	// 3b. Same idea for the status-GET connection (getLegStatus/reconcile/caller-lookup/device
	// resolve) — without this the FIRST post-boot status check still cold-handshakes even though
	// every later one on this handle resumes.
	warmStatusConnection();

	// 4. #100: cold-prime EVERY call slot's POST TLS session (keep-alive) in the background so a
	// cold-start concurrent burst RESUMES each per-call POST open instead of paying the S3's ~1s
	// software ECDHE. One-shot, off this task. (GET stays cold per call — see prewarmAllSlots.)
	if (xTaskCreateWithCaps(&TelephonyAnchorClient::prewarmTaskTrampoline, "tel_prewarm", 6144, this, 4, nullptr, PD_TASK_STACK_CAPS) != pdPASS)
	{
		ESP_LOGW(TAG, "start: failed to spawn slot pre-warm worker (first concurrent burst pays cold handshakes)");
	}

	return true;
}

void TelephonyAnchorClient::stop()
{
	shutdownImpl();
}

void TelephonyAnchorClient::shutdownImpl()
{
	{
		std::lock_guard<std::mutex> lock(_mutex);
		if (!_running)
		{
			return;
		}
		_running   = false;
		_connected = false;
	}

	// #43: stop the WS client first so handleWsEvent() enqueues nothing more, then JOIN and
	// tear down the worker pool BEFORE the streams/clients its work touches (stopMediaStreams,
	// getLegStatus) — otherwise a worker could run blocking I/O against half-freed state.
	if (_wsClient)
	{
		esp_websocket_client_stop(_wsClient);
	}
	stopWsWorkers();

	stopAllMediaStreams();
	closePostClient();   // free every slot's persistent warm POST/GET handle
	closeCtrlClient();
	closeStatusClient();

	if (_wsClient)
	{
		esp_websocket_client_destroy(_wsClient);
		_wsClient = nullptr;
	}

	std::lock_guard<std::mutex> lock(_mutex);
	_eventCb = nullptr;
	_audioCb = nullptr;
}

bool TelephonyAnchorClient::isConnected() const
{
	return _connected.load(std::memory_order_acquire);
}

bool TelephonyAnchorClient::isStreaming() const
{
	// "Streaming" = ANY call slot's POST stream is live (#100), NOT merely that a persistent warm
	// handle exists (kept alive between calls for TLS resumption). postLive is atomic and the slot
	// array is fixed, so no lock is needed to scan it.
	for (const auto& s : _calls)
	{
		if (s.postLive.load(std::memory_order_acquire)) return true;
	}
	return false;
}

bool TelephonyAnchorClient::makeCall(const std::string& destination, std::string* ownLegOut)
{
	if (ownLegOut) ownLegOut->clear();
	{
		std::lock_guard<std::mutex> lock(_mutex);
		// Gate on BOTH _running and _connected (audit #66). _connected alone lets a
		// makeCall that races stop()/disable proceed and set _outboundActive true
		// (below) after teardown began — the resurrection-critical WS-DATA path is
		// already _running-gated, so align origination with it. _running is cleared
		// first in stop(), so checking it here fails the call closed during shutdown.
		if (!_running.load(std::memory_order_acquire) ||
		    !_connected.load(std::memory_order_acquire))
		{
			ESP_LOGW(TAG, "Cannot make call: anchor not running/connected to Telephony");
			return false;
		}
	}

	// #100: mark an outbound makecall in flight BEFORE the POST and keep it marked until our own
	// leg is keyed onto a slot below (RAII clears it on every return path). The WS classifier reads
	// this to treat an early unmatched upset as our far leg, not a new inbound (the per-slot
	// successor to the old pre-POST _outboundActive flag, which guarded the same window).
	_outboundPending.fetch_add(1, std::memory_order_acq_rel);
	struct PendingDec {
		std::atomic<int>& c;
		~PendingDec() { c.fetch_sub(1, std::memory_order_acq_rel); }
	} pendingDec{_outboundPending};

	// Refresh the OAuth token if it's near expiry. Safe here: no media streams are
	// open at call-origination time, so a re-issue can't kill a live stream.
	ensureToken();

	std::string baseUrl, sourceDn, deviceId;
	{
		std::lock_guard<std::mutex> lock(_mutex);
		baseUrl = _baseUrl;
		sourceDn = _sourceDn;
		deviceId = _deviceId;
	}

	// Prefer the device-specific makecall endpoint (the recommended Telephony transport) over the legacy
	// /callcontrol/{dn}/makecall. Resolve the device_id lazily — makeCall runs on the tel_makecall
	// worker, so the blocking GET is fine here.
	if (deviceId.empty() && resolveDevice())
	{
		std::lock_guard<std::mutex> lock(_mutex);
		deviceId = _deviceId;
	}

	const std::string legacyUrl = baseUrl + "/callcontrol/" + sourceDn + "/makecall";
	auto deviceUrl = [&](const std::string& id) {
		return baseUrl + "/callcontrol/" + sourceDn + "/devices/" + urlEncode(id) + "/makecall";
	};
	std::string makeCallUrl = deviceId.empty() ? legacyUrl : deviceUrl(deviceId);
	// Issue #56: JSON-escape the destination before concatenating it into the
	// control-plane POST body. Today isValidAor (RequestsHandler) rejects "/\ on the
	// SIP path, but this is the anchor's own trust boundary — any future non-SIP
	// caller (dashboard dial, automation) that reaches makeCall without that filter
	// must not be able to inject control characters or break out of the JSON string.
	const std::string postData =
		"{\"destination\":\"" + jsonEscapeString(destination) + "\"}";

	// #100: the per-call slot is keyed by the participant id, which we only learn from the makecall
	// response (result.id). So we mark "outbound in flight" on the slot AFTER resolveOutboundLeg
	// below (keyed by ownLeg), not before the POST. resolveOutboundLeg parses the POST response
	// synchronously, so the slot exists before Telephony's WS upset for it arrives.

	// Capture the makecall RESPONSE BODY (not just the status) so we can read result.id — the
	// initiator's OWN leg on our DN, which is the leg Telephony authorizes us to stream/drop. (httpPostBody
	// uses a fresh client; performCtrl's persistent handle does not expose the body.)
	int status = 0;
	std::string respBody;
	bool success = httpPostBody(makeCallUrl, "application/json", postData, respBody, &status);

	// A device-path 404 means the cached device_id went stale (registration flap). Re-resolve once
	// on a fresh id and retry; if that still fails, fall back to the legacy endpoint.
	if (!success && !deviceId.empty() && status == 404)
	{
		ESP_LOGW(TAG, "makeCall: device path 404 — re-resolving device_id");
		{
			std::lock_guard<std::mutex> lock(_mutex);
			_deviceId.clear();
		}
		std::string freshId;
		if (resolveDevice())
		{
			std::lock_guard<std::mutex> lock(_mutex);
			freshId = _deviceId;
		}
		if (!freshId.empty())
		{
			status = 0; respBody.clear();
			success = httpPostBody(deviceUrl(freshId), "application/json", postData, respBody, &status);
		}
		if (!success)
		{
			ESP_LOGW(TAG, "makeCall: falling back to legacy makecall endpoint");
			status = 0; respBody.clear();
			success = httpPostBody(legacyUrl, "application/json", postData, respBody, &status);
		}
	}

	if (success)
	{
		// Select the leg WE control: makecall result.id, else the direct_control leg in the live
		// participant list (audit #76 — NOT a destination digit-suffix match, which selects the
		// uncontrollable far leg and re-triggers the #40 403). We deliberately do NOT adopt the
		// participant id Telephony later surfaces over the WS — that can be the far leg, on which a
		// specific-id GET/drop returns 403 (issue #40). Drop/media key off this owned id.
		std::string ownLeg = resolveOutboundLeg(respBody, destination);
		if (ownLegOut) *ownLegOut = ownLeg;   // #100: let the engine bind this call's session now
		if (!ownLeg.empty())
		{
			// Alloc THIS call's slot (startRxIfNeeded find-or-claims it for ownLeg) + prime the GET
			// loop, then mark the slot outbound-in-flight so the WS upsets for ownLeg classify as
			// ours and the tick() watchdog can detect a makecall that never produced media.
			if (startRxIfNeeded(ownLeg))
			{
				std::lock_guard<std::mutex> lock(_mutex);
				CallSlot* slot = slotForLocked(ownLeg);
				if (slot)
				{
					slot->outboundActive.store(true, std::memory_order_release);
					slot->outboundAnswered.store(false, std::memory_order_release);
					slot->outboundActiveSetUs = esp_timer_get_time();
				}
			}
			else
			{
				ESP_LOGW(TAG, "makeCall: all %d call slots busy — no slot for %s", POCKETDIAL_MAX_ANCHOR_CALLS, ownLeg.c_str());
			}
			ESP_LOGI(TAG, "Successfully initiated call to %s (own leg %s)", destination.c_str(), ownLeg.c_str());
		}
		else
		{
			ESP_LOGW(TAG, "makeCall: initiated %s but could not resolve own leg id — teardown will rely on reconcile", destination.c_str());
		}
	}
	else
	{
		ESP_LOGE(TAG, "makeCall request failed (status=%d)", status);
		// No slot was allocated (we alloc only after resolveOutboundLeg), so nothing to clear.
	}
	return success;
}

bool TelephonyAnchorClient::dropCall(const std::string& participantId)
{
	std::string baseUrl, sourceDn;
	{
		std::lock_guard<std::mutex> lock(_mutex);
		if (!_connected.load(std::memory_order_acquire))
		{
			return false;
		}
		baseUrl = _baseUrl;
		sourceDn = _sourceDn;
	}

	// Resolve which leg to drop. The caller passes the session's own participant id; only the
	// rare registration-miss path (no id ever correlated) falls back to asking Telephony which
	// participant is live on the DN (single-leg best effort — see reconcileParticipantId).
	std::string partId = participantId;
	if (partId.empty())
	{
		partId = reconcileParticipantId();
		if (!partId.empty())
		{
			ESP_LOGI(TAG, "dropCall: reconciled live participant %s", partId.c_str());
		}
	}
	if (partId.empty())
	{
		return false;
	}

	// #94 — free THIS call's audio-stream sockets BEFORE opening the drop connection. Each active
	// call holds 2 TLS sockets (GET + POST) over the W5500-MACRAW LWIP pool; freeing them gives
	// the drop POST room (else it fails with sock<0 / mbedtls alloc-fail and the PSTN leg lingers).
	// stopMediaStreams(partId) frees this participant's slot; its per-slot _tearingDown gate makes
	// it idempotent if the WS 'Dropped' event races us. Runs on the off-SIP tel_dropcall worker.
	stopMediaStreams(partId);

	// Trigger drop via HTTP POST /callcontrol/{sourceDn}/participants/{participantId}/drop
	// on the persistent control connection — fast teardown, no fresh handshake.
	std::string dropUrl = baseUrl + "/callcontrol/" + sourceDn + "/participants/" + partId + "/drop";

	int status = 0;
	// The Telephony participant-action endpoint requires an application/json body — the
	// reference client/server posts "{}" with Content-Type application/json (see the
	// call-control-examples server controlParticipant()). An empty body with no
	// Content-Type (the old call) is rejected, so the drop silently never fired and
	// the PSTN leg lingered until Telephony's own timeout. makeCall already does this right.
	bool success = performCtrl(dropUrl, "application/json", "{}", &status);
	if (success)
	{
		ESP_LOGI(TAG, "Successfully dropped participant %s", partId.c_str());
	}
	else
	{
		ESP_LOGE(TAG, "dropCall request failed for participant %s (status=%d)", partId.c_str(), status);
	}
	return success;
}

bool TelephonyAnchorClient::answerCall(const std::string& participantId)
{
	std::string partId = participantId, baseUrl, sourceDn;
	{
		std::lock_guard<std::mutex> lock(_mutex);
		if (!_connected.load(std::memory_order_acquire))
		{
			return false;
		}
		baseUrl = _baseUrl;
		sourceDn = _sourceDn;
	}
	if (partId.empty())
	{
		return false;
	}

	// Answer the inbound participant the route point is offering us: POST
	// /callcontrol/{dn}/participants/{id}/answer on the persistent control connection.
	// Telephony then connects the PSTN leg, flips the participant to Connected, and the
	// existing Upset→Connected path opens the PCM streams (startMediaStreams).
	//
	// NOTE: a route point configured as an *External Call Flow* app may instead expect
	// /route (route the call into the app) rather than /answer. If a deployment's
	// inbound calls never connect, this action string is the first thing to flip.
	std::string answerUrl = baseUrl + "/callcontrol/" + sourceDn + "/participants/" + partId + "/answer";

	int status = 0;
	// Same as drop: the participant-action endpoint wants an application/json "{}"
	// body (call-control-examples controlParticipant()), not an empty body.
	bool answered = performCtrl(answerUrl, "application/json", "{}", &status);
	if (answered)
	{
		ESP_LOGI(TAG, "Answered inbound participant %s", partId.c_str());
	}
	else
	{
		// A route point that auto-connects the PSTN leg can reject /answer on an
		// already-Connected participant — not fatal. The media streams below carry the audio.
		ESP_LOGW(TAG, "answerCall: /answer POST status=%d for %s (continuing to media)", status, partId.c_str());
	}

	// Media is normally already up: the inbound classifier pre-warms BOTH streams during the
	// local ring so audio cuts through at pickup. This is the FALLBACK — open them now only if
	// that pre-open hasn't taken (e.g. Telephony rejected a pre-answer stream and only accepts it now,
	// post-/answer). The startMediaStreams re-check makes a concurrent pre-warm safe. Runs on
	// the tel_answer worker (12 KB stack, TLS-capable).
	// Open the streams only if THIS slot isn't already live (the inbound classifier pre-warms both
	// during the local ring; startMediaStreams re-checks under the slot lock, so a concurrent
	// pre-warm is safe).
	bool slotLive = false;
	{
		CallSlot* s = nullptr;
		{ std::lock_guard<std::mutex> lock(_mutex); s = slotForLocked(partId); }
		if (s) { std::lock_guard<std::mutex> pl(s->postMutex); slotLive = s->postLive.load(std::memory_order_acquire); }
	}
	if (!slotLive && !startMediaStreams(partId))
	{
		ESP_LOGE(TAG, "answerCall: startMediaStreams failed for participant %s", partId.c_str());
		return false;
	}
	return true;
}

void TelephonyAnchorClient::setEventCallback(EventCallback cb)
{
	std::lock_guard<std::mutex> lock(_mutex);
	_eventCb = cb;
}

bool TelephonyAnchorClient::writeAudio(std::string_view participantId, const int16_t* pcmSamples, size_t count)
{
	if (pcmSamples == nullptr || count == 0)
	{
		return false;
	}

	// #100: route to the call's slot. Snapshot the slot pointer under _mutex, then operate under
	// the slot's own postMutex — the slot array never moves, so the pointer stays valid; if the
	// slot was torn down meanwhile, the postLive/postClient check below catches it.
	CallSlot* slot = nullptr;
	{
		std::lock_guard<std::mutex> lock(_mutex);
		slot = slotForLocked(participantId);
	}
	if (!slot)
	{
		return false;
	}

	std::lock_guard<std::mutex> lock(slot->postMutex);
	// Only write while THIS slot's stream is LIVE. The handle persists between calls (warm for
	// resumption) but has no open request then, so guard on postLive, not just the handle.
	if (!slot->postLive.load(std::memory_order_acquire) || !slot->postClient)
	{
		return false;
	}

	// esp_http_client_open(-1) sets the Transfer-Encoding: chunked header, but
	// esp_http_client_write() is a RAW passthrough to esp_transport_write() — IDF
	// does NOT add the chunk framing it promised (reads are auto-de-chunked,
	// writes are not; verified in esp_http_client.c:1887). So we frame each write
	// ourselves per RFC 9112 §7.1:   <size-hex>\r\n <payload> \r\n
	// Without this, Telephony's HTTP parser reads the first PCM bytes as a chunk-size
	// line, gets garbage, and silently discards the stream — the far end hears
	// nothing while every write reports success. One buffer + one write keeps a
	// whole chunk per TCP segment (helps the spec's "minimize jitter" note). The
	// static buffer is safe: all writers are serialized by _postMutex.
	size_t rawLen = count * sizeof(int16_t);
	// #100: STACK-local (was static) — N concurrent slots write on different postMutexes, so a
	// shared static buffer would race across calls. ~1 KB on the media-pump stack is fine.
	char chunkBuf[8 + 1024 + 2]; // "%X\r\n" header + payload (<=1024) + CRLF
	if (rawLen > 1024)
	{
		return false; // larger than any real audio frame; refuse rather than split
	}

	int hdrLen = snprintf(chunkBuf, sizeof(chunkBuf), "%X\r\n", static_cast<unsigned>(rawLen));
	std::memcpy(chunkBuf + hdrLen, pcmSamples, rawLen);
	chunkBuf[hdrLen + rawLen]     = '\r';
	chunkBuf[hdrLen + rawLen + 1] = '\n';
	const int total = hdrLen + static_cast<int>(rawLen) + 2;

	int written = esp_http_client_write(slot->postClient, chunkBuf, total);

	// #100: only the failure case logs now. The old per-frame cadence/peak log used a shared
	// `static` counter (raced across N concurrent slots) and flooded the UART at multi-call scale —
	// dropping serial lines and burning CPU on the 20 ms media pump. A short write still warns.
	if (written != total)
	{
		// %.*s, not %s: participantId is a string_view now (issue #218 follow-up)
		// and is not guaranteed null-terminated.
		ESP_LOGW(TAG, "POST writeAudio short/failed write rc=%d (want %d) for %.*s", written, total,
			static_cast<int>(participantId.size()), participantId.data());
	}
	return (written == total);
}

void TelephonyAnchorClient::registerAudioRxCallback(AudioRxCallback cb)
{
	std::lock_guard<std::mutex> lock(_mutex);
	_audioCb = cb;
}

// ── #100: per-call slot helpers (caller holds _mutex) ───────────────────────────
TelephonyAnchorClient::CallSlot* TelephonyAnchorClient::slotForLocked(std::string_view participantId)
{
	if (participantId.empty()) return nullptr;
	for (auto& s : _calls)
	{
		if (s.participantId == participantId) return &s;
	}
	return nullptr;
}

TelephonyAnchorClient::CallSlot* TelephonyAnchorClient::allocSlotLocked(const std::string& participantId)
{
	if (participantId.empty()) return nullptr;
	// Re-entrant upset for an already-tracked participant: reuse its slot.
	for (auto& s : _calls)
	{
		if (s.participantId == participantId) return &s;
	}
	for (auto& s : _calls)
	{
		if (s.participantId.empty())
		{
			s.participantId = participantId;
			return &s;
		}
	}
	return nullptr;   // all POCKETDIAL_MAX_ANCHOR_CALLS slots busy
}

void TelephonyAnchorClient::freeSlotLocked(CallSlot& slot)
{
	slot.participantId.clear();
	slot.inboundSignaledPartId.clear();
	slot.farPartId.clear();
	slot.outboundActive.store(false, std::memory_order_release);
	slot.outboundAnswered.store(false, std::memory_order_release);
	slot.outboundActiveSetUs = 0;
	slot.upsetInFlight.store(false, std::memory_order_release);
	slot.upsetPending.store(false, std::memory_order_release);
}

// ── Private Helper Functions ───────────────────────────────────────────────

bool TelephonyAnchorClient::fetchToken()
{
	std::string tokenUrl;
	std::string clientId, clientSecret;
	{
		std::lock_guard<std::mutex> lock(_mutex);
		tokenUrl = _baseUrl + "/connect/token";
		clientId = _clientId;
		clientSecret = _clientSecret;
	}

	esp_http_client_handle_t client = makeAuthedClient(tokenUrl, HTTP_METHOD_POST, 1024);
	if (!client)
	{
		ESP_LOGE(TAG, "Failed to init HTTP client for fetchToken");
		return false;
	}

	esp_http_client_set_header(client, "Content-Type", "application/x-www-form-urlencoded");

	// Percent-encode both credential values: a real carrier secret commonly
	// contains '+', '/', '=' (base64-shaped), any of which corrupts an
	// unencoded x-www-form-urlencoded body -- same urlEncode() this file
	// already uses for the device_id path segment above.
	std::string body = "grant_type=client_credentials&client_id=" + urlEncode(clientId) +
	                   "&client_secret=" + urlEncode(clientSecret);

	bool success = false;
	esp_err_t err = esp_http_client_open(client, body.length());
	if (err == ESP_OK)
	{
		int writeBytes = esp_http_client_write(client, body.c_str(), body.length());
		if (writeBytes >= 0)
		{
			int fetch_res = esp_http_client_fetch_headers(client);
			int status = esp_http_client_get_status_code(client);
			ESP_LOGI(TAG, "Token request HTTP status: %d, fetch_res: %d, chunked: %d", 
			         status, fetch_res, esp_http_client_is_chunked_response(client));
			if (status == 200)
			{
				std::string tokenStr;
				if (readJsonStringField(client, "access_token", tokenStr))
				{
					std::lock_guard<std::mutex> lock(_mutex);
					_accessToken = tokenStr;
					_tokenObtainedUs = esp_timer_get_time();
					_tokenLifetimeUs = decodeJwtLifetimeUs(_accessToken);
					if (_wsClient)
					{
						// Issue #336 caveat, found reviewing this call while fixing that issue:
						// per connectWs()'s own comment on this same API,
						// esp_websocket_client_set_headers() no-ops with ESP_ERR_INVALID_ARG
						// unless the client is CONNECTED at the moment of the call. This proactive
						// refresh (called right after a successful fetchToken(), independent of WS
						// state) only actually lands when the WS happens to still be connected —
						// which is fine for a refresh ahead of expiry, but is NOT what fixes a
						// reconnect after the WS has already dropped with a stale token: that path
						// never reaches here at all (fetchToken() isn't re-called on disconnect).
						// requestRestartIfTokenStale()/WEBSOCKET_EVENT_DISCONNECTED below is what
						// actually handles the disconnected case, via a full stop()/start() that
						// rebuilds wsCfg.headers fresh at init time rather than patching this handle.
						std::string wsHeaders = "Authorization: Bearer " + _accessToken + "\r\n";
						esp_websocket_client_set_headers(_wsClient, wsHeaders.c_str());
					}
					ESP_LOGI(TAG, "Retrieved access token (len=%d, lifetime=%llds)",
					         (int)_accessToken.length(),
					         (long long)(_tokenLifetimeUs / 1000000));
					success = true;
				}
			}
			else
			{
				ESP_LOGE(TAG, "Token request returned HTTP %d", status);
			}
		}
		else
		{
			ESP_LOGE(TAG, "Token failed to write body: %d", writeBytes);
		}
		esp_http_client_close(client);
	}
	else
	{
		ESP_LOGE(TAG, "Token HTTP connection failed to open: %s", esp_err_to_name(err));
	}

	esp_http_client_cleanup(client);
	return success;
}

bool TelephonyAnchorClient::tokenExpiringSoon() const
{
	// Refresh once we're within 5 minutes of the JWT's declared expiry. The
	// comparison itself is telephony::tokenIsExpiringSoon() (TelephonyAnchorLogic.hpp,
	// issue #336) -- host-tested there; this just supplies the live clock.
	constexpr int64_t kRefreshMarginUs = 5LL * 60 * 1000000;
	return telephony::tokenIsExpiringSoon(esp_timer_get_time(), _tokenObtainedUs,
	                                       _tokenLifetimeUs, kRefreshMarginUs);
}

bool TelephonyAnchorClient::ensureToken()
{
	{
		std::lock_guard<std::mutex> lock(_mutex);
		if (!tokenExpiringSoon()) return true;
	}

	// Never re-issue a token while media streams are live: Telephony invalidates the
	// previous token the instant a new one is granted, which would tear down the
	// chunked GET/POST streams holding the old token mid-call. Refresh only
	// happens between calls (makeCall is invoked before any stream is opened).
	// #100: a CALL is up if ANY slot has a live POST stream (postLive) or an open GET handle.
	// Each handle is read under the per-slot mutex that actually guards its lifecycle (postMutex/
	// getMutex), never nested. The persistent warm postClient (postLive=false) is NOT a live call,
	// so test postLive, not handle!=null — else the warm handle would wedge token refresh forever.
	bool streamsActive = false;
	for (auto& s : _calls)
	{
		if (s.postLive.load(std::memory_order_acquire)) { streamsActive = true; break; }
		std::lock_guard<std::mutex> getLock(s.getMutex);
		if (s.getClient != nullptr) { streamsActive = true; break; }
	}
	if (streamsActive)
	{
		ESP_LOGW(TAG, "Token near expiry but media streams active — deferring refresh");
		return true;
	}

	ESP_LOGI(TAG, "Access token near expiry — refreshing");
	return fetchToken();
}

// Issue #336: connectWs() bakes _accessToken into wsCfg.headers once, at
// esp_websocket_client_init() time. esp_websocket_client's own internal
// reconnect_timeout_ms retry logic reuses that same init'd handle forever,
// so once the token expires, every retry re-sends the identical stale Bearer
// header and gets the identical 401 -- silently, indefinitely, with nothing
// else in the tree ever telling the WS side a fresh token exists. Reconnect
// with a stale token is unfixable in place: esp_websocket_client_set_headers()
// is documented as "must stop the client first if it has been connected",
// and connectWs()'s own comment already records a harder finding from this
// project's own testing -- calling it pre-start() silently no-ops the header
// instead of erroring, which is worse than the documented precondition.
// Cheaper and already correct: reuse the existing #65 restart machinery
// (_restartRequested -> tick() -> restartTaskTrampoline, off the SIP task)
// rather than build a second stop/destroy/reconnect path. restartTaskTrampoline's
// stop()+start() cycle calls fetchToken() unconditionally before connectWs(),
// so it always reconnects with a genuinely current token, not just a
// refreshed-if-due one.
void TelephonyAnchorClient::requestRestartIfTokenStale()
{
	// Guard against the restart-storm this fix could otherwise cause: stop()
	// (called by restartTaskTrampoline, and by shutdown) clears _running BEFORE
	// calling esp_websocket_client_stop(), which itself fires a DISCONNECTED
	// event for the dying client on its way out. Without this gate, that event
	// would re-request a restart while the current one is still tearing down,
	// and tick() would spawn a second restartTaskTrampoline the moment
	// _restartInFlight clears -- trading a 401 loop for a restart loop.
	// _running==false covers both shutdown and "already mid-restart" here,
	// since restartTaskTrampoline's stop() clears it before start() sets it
	// again. handleWsEvent's WEBSOCKET_EVENT_DATA case already gates the same
	// way for the analogous reason (line ~2400).
	if (!_running.load(std::memory_order_acquire)) return;
	if (!tokenExpiringSoon()) return;
	// _restartInFlight is checked by tick(), not here -- storing true again
	// while a restart is already running is a harmless redundant request,
	// same as the #65 leak-count path above already relies on.
	_restartRequested.store(true, std::memory_order_release);
	ESP_LOGW(TAG, "WS disconnected/errored with an expiring token — requesting anchor restart to refresh it");
}

bool TelephonyAnchorClient::connectWs()
{
	// Convert base https:// URL to wss:// for call control websocket
	std::string wsUrl;
	std::string token;
	{
		std::lock_guard<std::mutex> lock(_mutex);
		wsUrl = _baseUrl;
		token = _accessToken;
	}

	if (wsUrl.rfind("https://", 0) == 0)
	{
		wsUrl = "wss://" + wsUrl.substr(8) + "/callcontrol/ws";
	}
	else if (wsUrl.rfind("http://", 0) == 0)
	{
		wsUrl = "ws://" + wsUrl.substr(7) + "/callcontrol/ws";
	}
	else
	{
		wsUrl = "wss://" + wsUrl + "/callcontrol/ws";
	}

	// The Bearer token MUST be supplied via wsCfg.headers (the config path), which
	// is what feeds the handshake request. esp_websocket_client_set_headers() does
	// NOT work for handshake auth — it early-returns ESP_ERR_INVALID_ARG unless the
	// client is already CONNECTED, so calling it before start() silently set no
	// header and Telephony rejected the unauthenticated upgrade with HTTP 401. Each header
	// line must be CRLF-terminated. init() strdup's this string, so the local is safe.
	std::string authHeader = "Authorization: Bearer " + token + "\r\n";

	esp_websocket_client_config_t wsCfg = {};
	wsCfg.uri = wsUrl.c_str();
	wsCfg.headers = authHeader.c_str();
	wsCfg.crt_bundle_attach = esp_crt_bundle_attach;
	wsCfg.task_stack = 6144; // #43: the event handler is now lightweight (parse+enqueue); the
	                         // blocking HTTP moved to the tel_wsw worker pool, so the WS task no
	                         // longer needs headroom for two in-flight HTTP sessions.
	wsCfg.buffer_size = 4096;
	// #93 — keep the control WebSocket warm so it never idles out into a full TLS
	// reconnect (the S3 has no ECC accelerator, so a cold WSS handshake is software-ECDHE
	// bound, ~0.5-1 s). PINGs hold the channel open; pingpong_timeout declares it dead and
	// triggers an auto-reconnect if PONGs stop; the explicit reconnect/network timeouts
	// replace the 10 s defaults the client warned about at boot.
	wsCfg.ping_interval_sec    = 20;
	wsCfg.pingpong_timeout_sec = 20;
	wsCfg.keep_alive_enable    = true;
	wsCfg.reconnect_timeout_ms = 5000;
	wsCfg.network_timeout_ms   = 10000;

	esp_websocket_client_handle_t wsClient = esp_websocket_client_init(&wsCfg);
	if (!wsClient)
	{
		return false;
	}

	esp_err_t err = esp_websocket_register_events(wsClient, WEBSOCKET_EVENT_ANY,
	                                               &TelephonyAnchorClient::wsEventTrampoline, this);
	if (err != ESP_OK)
	{
		esp_websocket_client_destroy(wsClient);
		return false;
	}

	{
		std::lock_guard<std::mutex> lock(_mutex);
		_wsClient = wsClient;
	}

	err = esp_websocket_client_start(wsClient);
	if (err != ESP_OK)
	{
		esp_websocket_client_destroy(wsClient);
		std::lock_guard<std::mutex> lock(_mutex);
		_wsClient = nullptr;
		return false;
	}

	return true;
}

// getParticipantStatus() removed (chore #75): it issued the specific-id
// GET /callcontrol/{dn}/participants/{id} probe that returns HTTP 403 for a leg
// this route point cannot directly control (issue #40). Its single caller (the WS
// upset handler) was migrated to the list-based getLegStatus(legId) in PR #39.
// Deleted so a future caller can't reintroduce the wrong-leg 403.

// Generalized authed GET → full response body. Snapshots the token under _mutex, then does all
// blocking I/O lock-free. close()+cleanup() on every exit path. Returns true only on a 2xx with a
// clean body read; *statusOut carries the HTTP status (or -1) so callers can distinguish "no
// evidence" (transient/non-200) from a definitive answer.
// #107/pcap-driven fix: was a fresh esp_http_client_init+cleanup EVERY call — save_client_session
// bought nothing because destroying the handle throws the cached ticket away with it. Now mirrors
// performCtrl/postClient: one persistent _statusClient, closed (not cleaned up) between calls so a
// reopen RESUMES, rebuilt+retried once on a stale/broken handle. Every caller (getLegStatus,
// reconcileParticipantId, getParticipantCaller, resolveDevice, resolveOutboundLeg's fallback) hits
// this same path, so a burst of N concurrent calls each resolving their own leg's status now pays
// N sequential ~100-150ms resumed opens instead of N concurrent ~800ms-1s cold ECDHEs fighting the
// S3's single crypto-bound core for CPU.
bool TelephonyAnchorClient::httpGetBody(const std::string& url, std::string& bodyOut, int* statusOut)
{
	if (statusOut) *statusOut = -1;
	bodyOut.clear();

	std::string token;
	{
		std::lock_guard<std::mutex> lock(_mutex);
		token = _accessToken;
	}

	std::lock_guard<std::mutex> statusLock(_statusMutex);

	bool ok = false;
	for (int attempt = 0; attempt < 2; ++attempt)
	{
		if (!_statusClient)
		{
			_statusClient = makeAuthedClient(url, HTTP_METHOD_GET, 1024, token);
			if (!_statusClient)
			{
				ESP_LOGE(TAG, "httpGetBody: failed to init HTTP client");
				return false;
			}
		}
		else
		{
			esp_http_client_set_url(_statusClient, url.c_str());
			esp_http_client_set_method(_statusClient, HTTP_METHOD_GET);
			// Token may have rotated since the handle was created.
			if (!token.empty())
			{
				std::string authHeader = "Bearer " + token;
				esp_http_client_set_header(_statusClient, "Authorization", authHeader.c_str());
			}
		}

		esp_err_t err = esp_http_client_open(_statusClient, 0);
		if (err == ESP_OK)
		{
			esp_http_client_fetch_headers(_statusClient);
			int status = esp_http_client_get_status_code(_statusClient);

			// Drain the whole body regardless of status so the connection is left clean.
			std::vector<char> buffer;
			char tempBuf[512];
			int readBytes = 0;
			while ((readBytes = esp_http_client_read(_statusClient, tempBuf, sizeof(tempBuf))) > 0)
			{
				buffer.insert(buffer.end(), tempBuf, tempBuf + readBytes);
			}
			esp_http_client_close(_statusClient);   // keep handle+session warm; NOT cleanup

			if (readBytes < 0)
			{
				ESP_LOGE(TAG, "httpGetBody: HTTP read error %d (status=%d)", readBytes, status);
			}
			else
			{
				if (statusOut) *statusOut = status;
				bodyOut.assign(buffer.begin(), buffer.end());
				ok = (status >= 200 && status < 300);
				break;
			}
		}
		else
		{
			ESP_LOGW(TAG, "httpGetBody: open failed (%s)%s", esp_err_to_name(err),
			         attempt == 0 ? " — reconnecting" : "");
		}

		// Open or read failed: the reused handle may be riding a connection the server already
		// idled out. Rebuild fresh and retry once (degrades to a cold handshake, never a failed
		// call) rather than leaving a poisoned handle warm for next time.
		esp_http_client_cleanup(_statusClient);
		_statusClient = nullptr;
	}

	return ok;
}

// POST with a body and return the response body (and HTTP status). Mirrors httpGetBody but for the
// makecall, whose result.id we need to read. Uses a fresh client (the persistent _ctrlClient that
// performCtrl drives via esp_http_client_perform does not surface the body). close()+cleanup() on
// every path; *statusOut carries the HTTP status (or -1).
bool TelephonyAnchorClient::httpPostBody(const std::string& url, const char* contentType, const std::string& body, std::string& respBody, int* statusOut)
{
	if (statusOut) *statusOut = -1;
	respBody.clear();

	std::string token;
	{
		std::lock_guard<std::mutex> lock(_mutex);
		token = _accessToken;
	}

	esp_http_client_handle_t client = makeAuthedClient(url, HTTP_METHOD_POST, 1024, token);
	if (!client)
	{
		ESP_LOGE(TAG, "httpPostBody: failed to init HTTP client");
		return false;
	}
	if (contentType)
	{
		esp_http_client_set_header(client, "Content-Type", contentType);
	}

	bool ok = false;
	esp_err_t err = esp_http_client_open(client, static_cast<int>(body.length()));
	if (err == ESP_OK)
	{
		int wlen = (body.empty()) ? 0 : esp_http_client_write(client, body.c_str(), body.length());
		if (wlen >= 0)
		{
			esp_http_client_fetch_headers(client);
			int status = esp_http_client_get_status_code(client);
			if (statusOut) *statusOut = status;

			std::vector<char> buffer;
			char tempBuf[512];
			int readBytes = 0;
			while ((readBytes = esp_http_client_read(client, tempBuf, sizeof(tempBuf))) > 0)
			{
				buffer.insert(buffer.end(), tempBuf, tempBuf + readBytes);
			}
			if (readBytes < 0)
			{
				ESP_LOGE(TAG, "httpPostBody: HTTP read error %d (status=%d)", readBytes, status);
			}
			else
			{
				respBody.assign(buffer.begin(), buffer.end());
				ok = (status >= 200 && status < 300);
			}
		}
		else
		{
			ESP_LOGE(TAG, "httpPostBody: write failed %d", wlen);
		}
		esp_http_client_close(client);
	}
	else
	{
		ESP_LOGE(TAG, "httpPostBody: open failed: %s", esp_err_to_name(err));
	}

	esp_http_client_cleanup(client);
	return ok;
}

// The first participant id currently on our DN, or "" if none / on any error. Drives the drop
// fallback when no WS upset ever correlated an id (dropCall) and the wedge watchdog (tick worker).
std::string TelephonyAnchorClient::reconcileParticipantId()
{
	std::string url;
	{
		std::lock_guard<std::mutex> lock(_mutex);
		url = _baseUrl + "/callcontrol/" + _sourceDn + "/participants";
	}

	std::string body;
	int status = 0;
	if (!httpGetBody(url, body, &status) || status != 200)
	{
		ESP_LOGW(TAG, "reconcileParticipantId: GET failed (status=%d)", status);
		return "";
	}

	cJSON* root = cJSON_Parse(body.c_str());
	if (!root)
	{
		ESP_LOGE(TAG, "reconcileParticipantId: JSON parse failed");
		return "";
	}
	CJsonDeleter deleter{root};

	if (!cJSON_IsArray(root))
	{
		return "";
	}

	// Single-leg assumption: our DN bridges one call at a time via MediaBridge, so the first
	// participant IS the only one. A multi-leg DN would need a target match instead of "first" —
	// flag this if such a deployment ever appears. A leg ending between this GET and the drop that
	// follows is a benign 404 at the drop POST.
	cJSON* elem = nullptr;
	cJSON_ArrayForEach(elem, root)
	{
		if (!cJSON_IsObject(elem)) continue;
		cJSON* id = cJSON_GetObjectItem(elem, "id");
		if (cJSON_IsString(id) && id->valuestring && id->valuestring[0])
		{
			return std::string(id->valuestring);
		}
		if (cJSON_IsNumber(id))
		{
			char idbuf[24];
			snprintf(idbuf, sizeof(idbuf), "%d", id->valueint);
			return std::string(idbuf);
		}
	}
	return "";
}

// Status of one specific leg, read from the participant LIST (GET /callcontrol/{dn}/participants
// then find id). This is the controllable-scope read Telephony honours, unlike GET .../participants/{id}
// which 403s for a leg this DN does not directly control (issue #40). "" if the leg isn't listed.
std::string TelephonyAnchorClient::getLegStatus(const std::string& legId)
{
	if (legId.empty()) return "";
	std::string url;
	{
		std::lock_guard<std::mutex> lock(_mutex);
		url = _baseUrl + "/callcontrol/" + _sourceDn + "/participants";
	}
	std::string body;
	int status = 0;
	if (!httpGetBody(url, body, &status) || status != 200)
	{
		ESP_LOGW(TAG, "getLegStatus: GET /participants failed (status=%d)", status);
		return "";
	}
	cJSON* root = cJSON_Parse(body.c_str());
	if (!root) return "";
	CJsonDeleter deleter{root};
	if (!cJSON_IsArray(root)) return "";

	cJSON* elem = nullptr;
	cJSON_ArrayForEach(elem, root)
	{
		if (!cJSON_IsObject(elem)) continue;
		cJSON* id = cJSON_GetObjectItem(elem, "id");
		char idbuf[24] = {0};
		if (cJSON_IsString(id) && id->valuestring) snprintf(idbuf, sizeof(idbuf), "%s", id->valuestring);
		else if (cJSON_IsNumber(id))               snprintf(idbuf, sizeof(idbuf), "%d", id->valueint);
		if (legId == idbuf)
		{
			cJSON* st = cJSON_GetObjectItem(elem, "status");
			if (cJSON_IsString(st) && st->valuestring) return std::string(st->valuestring);
			return "";
		}
	}
	return "";   // leg not on the DN (gone, or an id we don't own)
}

std::string TelephonyAnchorClient::getParticipantCaller(const std::string& legId)
{
	// Best-effort caller display for an inbound leg, from the live participant list: the
	// number (party_caller_id) first — that is literally the caller ID — then a CNAM
	// (party_caller_name) as a fallback. "" if unavailable. Blocking GET — call off the WS task.
	if (legId.empty()) return "";
	std::string url;
	{
		std::lock_guard<std::mutex> lock(_mutex);
		url = _baseUrl + "/callcontrol/" + _sourceDn + "/participants";
	}
	std::string body;
	int status = 0;
	if (!httpGetBody(url, body, &status) || status != 200) return "";
	cJSON* root = cJSON_Parse(body.c_str());
	if (!root) return "";
	CJsonDeleter deleter{root};
	if (!cJSON_IsArray(root)) return "";

	cJSON* elem = nullptr;
	cJSON_ArrayForEach(elem, root)
	{
		if (!cJSON_IsObject(elem)) continue;
		cJSON* id = cJSON_GetObjectItem(elem, "id");
		char idbuf[24] = {0};
		if (cJSON_IsString(id) && id->valuestring) snprintf(idbuf, sizeof(idbuf), "%s", id->valuestring);
		else if (cJSON_IsNumber(id))               snprintf(idbuf, sizeof(idbuf), "%d", id->valueint);
		if (legId != idbuf) continue;
		cJSON* cid = cJSON_GetObjectItem(elem, "party_caller_id");
		if (cJSON_IsString(cid) && cid->valuestring && cid->valuestring[0]) return std::string(cid->valuestring);
		cJSON* nm = cJSON_GetObjectItem(elem, "party_caller_name");
		if (cJSON_IsString(nm) && nm->valuestring && nm->valuestring[0]) return std::string(nm->valuestring);
		return "";
	}
	return "";
}

// Extract a participant "id" (string or number form) from a cJSON object, "" if absent.
static std::string legIdOf(cJSON* elem)
{
	cJSON* id = cJSON_GetObjectItem(elem, "id");
	if (cJSON_IsString(id) && id->valuestring && id->valuestring[0]) return std::string(id->valuestring);
	if (cJSON_IsNumber(id)) { char b[24]; snprintf(b, sizeof(b), "%d", id->valueint); return std::string(b); }
	return "";
}

// Resolve the leg WE control for an outbound makecall. This is the only id Telephony lets us
// stream/drop — a specific-id GET/drop on a leg we don't control returns 403 (issue #40).
//   1) result.id from the device-makecall response (the initiator's OWN leg on our DN). The
//      production path; present today.
//   2) Legacy fallback (no result.id — bare /makecall, or a deregistered source DN): pick the
//      CONTROLLABLE leg from the live participant list, i.e. one with direct_control == true
//      (Telephony only acts on legs we directly control — see HTTP API §7.4). Among controllable
//      legs, prefer the one whose party_dn matches _sourceDn (our own initiator leg).
//
// We deliberately do NOT fall back to a destination digit-suffix match (audit #76): that keys
// on the callee/FAR leg — exactly the leg class that 403'd in #40 — so a legacy-path guess could
// re-trigger the wrong-leg 403. If no controllable leg is found we FAIL CLOSED (return "") and
// let the reconcile/watchdog teardown handle it, rather than drop a guessed id.
std::string TelephonyAnchorClient::resolveOutboundLeg(const std::string& makecallRespBody, const std::string& /*destination*/)
{
	// 1) result.id from the makecall response.
	if (!makecallRespBody.empty())
	{
		cJSON* root = cJSON_Parse(makecallRespBody.c_str());
		if (root)
		{
			CJsonDeleter deleter{root};
			cJSON* result = cJSON_GetObjectItem(root, "result");
			if (result)
			{
				std::string rid = legIdOf(result);
				if (!rid.empty())
				{
					ESP_LOGI(TAG, "resolveOutboundLeg: result.id=%s (from makecall response)", rid.c_str());
					return rid;
				}
			}
		}
	}
	ESP_LOGW(TAG, "resolveOutboundLeg: no result.id in makecall response (len=%u) — falling back to live list",
	         static_cast<unsigned>(makecallRespBody.size()));

	// 2) Fallback: pick the CONTROLLABLE own leg from the live participant list.
	std::string url, srcDn;
	{
		std::lock_guard<std::mutex> lock(_mutex);
		url = _baseUrl + "/callcontrol/" + _sourceDn + "/participants";
		srcDn = _sourceDn;
	}
	// Digit form of our source DN, to prefer our own initiator leg among controllable ones.
	std::string srcDigits;
	for (char c : srcDn) if (c >= '0' && c <= '9') srcDigits.push_back(c);

	std::string body;
	int status = 0;
	if (!httpGetBody(url, body, &status) || status != 200) return "";
	cJSON* root = cJSON_Parse(body.c_str());
	if (!root) return "";
	CJsonDeleter deleter{root};
	if (!cJSON_IsArray(root)) return "";

	std::string firstControllable;   // any direct_control:true leg (own-leg fallback)
	cJSON* elem = nullptr;
	cJSON_ArrayForEach(elem, root)
	{
		if (!cJSON_IsObject(elem)) continue;
		cJSON* dc = cJSON_GetObjectItem(elem, "direct_control");
		// Only consider legs Telephony authorizes us to control. A missing field is treated as
		// NOT controllable — fail closed rather than guess (audit #76).
		if (!cJSON_IsBool(dc) || !cJSON_IsTrue(dc)) continue;

		std::string id = legIdOf(elem);
		if (id.empty()) continue;
		// #100: skip a leg already claimed by another concurrent call's slot. Without this, two
		// simultaneous originations (whose makecall responses lacked a distinct result.id) both
		// pick the SAME first-controllable leg here and collide — only one call ever bridges.
		{
			std::lock_guard<std::mutex> lock(_mutex);
			if (slotForLocked(id)) continue;
		}
		if (firstControllable.empty()) firstControllable = id;

		// Prefer the controllable leg whose party_dn IS our source DN — the initiator (own) leg.
		if (!srcDigits.empty())
		{
			cJSON* pdn = cJSON_GetObjectItem(elem, "party_dn");
			if (cJSON_IsString(pdn) && pdn->valuestring)
			{
				std::string pd;
				for (const char* p = pdn->valuestring; *p; ++p) if (*p >= '0' && *p <= '9') pd.push_back(*p);
				if (pd == srcDigits) return id;   // exact own-leg match
			}
		}
	}

	if (firstControllable.empty())
	{
		ESP_LOGW(TAG, "resolveOutboundLeg: no direct_control leg on DN — failing closed (reconcile/watchdog will tear down)");
	}
	return firstControllable;   // controllable leg (or "" → fail closed)
}

// Parse a Telephony /devices array, returning the best device_id: prefer a device that advertises a
// user_agent (a real registered endpoint) over a bare slot; otherwise the first device_id present.
// "" if none / on parse error.
std::string TelephonyAnchorClient::pickDeviceId(const std::string& body)
{
	cJSON* root = cJSON_Parse(body.c_str());
	if (!root) return "";
	CJsonDeleter deleter{root};
	if (!cJSON_IsArray(root)) return "";

	std::string firstId;
	cJSON* elem = nullptr;
	cJSON_ArrayForEach(elem, root)
	{
		if (!cJSON_IsObject(elem)) continue;
		cJSON* devId = cJSON_GetObjectItem(elem, "device_id");
		if (!cJSON_IsString(devId) || !devId->valuestring || !devId->valuestring[0]) continue;

		if (firstId.empty()) firstId = devId->valuestring;

		cJSON* ua = cJSON_GetObjectItem(elem, "user_agent");
		if (cJSON_IsString(ua) && ua->valuestring && ua->valuestring[0])
		{
			return std::string(devId->valuestring);   // registered endpoint — prefer it
		}
	}
	return firstId;
}

// GET /callcontrol/{dn}/devices → pickDeviceId → cache in _deviceId. Returns true on success.
bool TelephonyAnchorClient::resolveDevice()
{
	std::string url;
	{
		std::lock_guard<std::mutex> lock(_mutex);
		url = _baseUrl + "/callcontrol/" + _sourceDn + "/devices";
	}

	std::string body;
	int status = 0;
	if (!httpGetBody(url, body, &status) || status != 200)
	{
		ESP_LOGW(TAG, "resolveDevice: GET /devices failed (status=%d)", status);
		return false;
	}

	std::string devId = pickDeviceId(body);
	if (devId.empty())
	{
		ESP_LOGW(TAG, "resolveDevice: no usable device_id on DN");
		return false;
	}

	{
		std::lock_guard<std::mutex> lock(_mutex);
		_deviceId = devId;
	}
	ESP_LOGI(TAG, "resolveDevice: using device_id %s", devId.c_str());
	return true;
}

void TelephonyAnchorClient::setRewarmIntervalSec(uint32_t sec)
{
	// #107: live-applicable — the next idle tick uses the new cadence (0 disables). Reset the
	// stamp so a freshly-set interval is measured from now, not from the previous schedule.
	_rewarmIntervalSec.store(sec, std::memory_order_release);
	_lastRewarmUs.store(0, std::memory_order_release);
	ESP_LOGI(TAG, "TLS re-warm interval set to %u s (%s)", sec, sec ? "enabled" : "disabled");
}

void TelephonyAnchorClient::tick()
{
	// Runs inline on the SIP task at ≤1 Hz — MUST be non-blocking: only atomic reads, one timer
	// read, and (rarely) a worker spawn. No logging or allocation on the common path.

	// Issue #65 (L-1): too many leaked GET sockets — spawn a one-shot worker to do a full
	// stop()/start() reclaim OFF this task (stop()/start() block on TLS I/O). _restartInFlight
	// is a one-shot gate so repeated ticks can't stack restart workers. Checked before the
	// outboundActive gate because a leak can accumulate independent of an active outbound call.
	if (_restartRequested.load(std::memory_order_acquire) &&
	    !_restartInFlight.load(std::memory_order_acquire))
	{
		_restartInFlight.store(true, std::memory_order_release);
		if (xTaskCreate(&TelephonyAnchorClient::restartTaskTrampoline, "tel_restart", 6144, this, 5, nullptr) != pdPASS)
		{
			ESP_LOGE(TAG, "tick: failed to spawn anchor-restart worker");
			_restartInFlight.store(false, std::memory_order_release);
		}
	}

	// ── #107: idle TLS re-warm heartbeat ─────────────────────────────────────────
	// Keep the persistent POST media TLS session warm DURING IDLE so even the first call
	// after a long quiet stretch resumes (~1 RTT) instead of paying the S3's ~1s software-
	// ECDHE cold handshake at connect (the old answer-time dead air). Idle-gated: only when
	// the anchor is up, no outbound flag is set, and no call's POST stream is live. Cadence
	// is operator-configurable (default 1 h; 0 disables) so a different upstream's ticket
	// lifetime is a config change, not a recompile. Spawns a one-shot worker for the blocking
	// open/close — this tick (on the SIP task) never blocks. Placed BEFORE the outbound
	// reconcile gate below because re-warm runs precisely when NOT in an outbound call.
	// #100: "idle" = no slot has an outbound flag set and no slot is streaming. Scan the fixed
	// slot array (atomics, no lock).
	bool anyOutbound = false;
	for (const auto& s : _calls)
	{
		if (s.outboundActive.load(std::memory_order_acquire)) { anyOutbound = true; break; }
	}
	const bool anyStreaming = isStreaming();
	const uint32_t rewarmSec = _rewarmIntervalSec.load(std::memory_order_acquire);
	if (rewarmSec != 0 &&
	    _running.load(std::memory_order_acquire) &&
	    !anyOutbound &&
	    !anyStreaming &&
	    _outboundPending.load(std::memory_order_acquire) == 0 &&
	    !_rewarmInFlight.load(std::memory_order_acquire))
	{
		const int64_t now  = esp_timer_get_time();
		const int64_t last = _lastRewarmUs.load(std::memory_order_acquire);
		if (last == 0)
		{
			// First idle tick: seed so the first re-warm fires one full interval from now.
			_lastRewarmUs.store(now, std::memory_order_release);
		}
		else if (now - last >= static_cast<int64_t>(rewarmSec) * 1000000LL)
		{
			// Stamp BEFORE the spawn so the next-due math is correct even if the worker is slow.
			_lastRewarmUs.store(now, std::memory_order_release);
			_rewarmInFlight.store(true, std::memory_order_release);
			if (xTaskCreate(&TelephonyAnchorClient::rewarmTaskTrampoline, "tel_rewarm", 6144, this, 5, nullptr) != pdPASS)
			{
				ESP_LOGE(TAG, "tick: failed to spawn TLS re-warm worker");
				_rewarmInFlight.store(false, std::memory_order_release);
			}
		}
	}

	// #100: is ANY outbound slot wedged — flag set, no media, past the grace window? Such a slot's
	// makecall was accepted but never produced a participant/media; the reconcile worker frees it so
	// it stops occupying a concurrent-call slot. 15 s grace: a real outbound call yields its
	// participant upset within ~1 RTT, so a flag still set this long after makecall is a wedge.
	constexpr int64_t kWedgeGraceUs = 15LL * 1000000;
	const int64_t nowUs = esp_timer_get_time();
	bool anyWedged = false;
	{
		std::lock_guard<std::mutex> lock(_mutex);
		for (auto& s : _calls)
		{
			if (s.participantId.empty()) continue;
			if (!s.outboundActive.load(std::memory_order_acquire)) continue;
			if (s.postLive.load(std::memory_order_acquire)) continue;
			if (s.outboundActiveSetUs != 0 && nowUs - s.outboundActiveSetUs >= kWedgeGraceUs)
			{
				anyWedged = true;
				break;
			}
		}
	}
	if (!anyWedged) return;
	if (_reconcileInFlight.load(std::memory_order_acquire)) return;

	// #94: floor the reconcile cadence. While a call holds the anchor TLS sockets every
	// reconcile GET fails with sock<0, and the 1 Hz tick would otherwise busy-loop those
	// failed connects — burning CPU/heap and adding to the very socket pressure that wedges
	// teardown. Re-spawn at most once per kReconcileMinIntervalUs.
	constexpr int64_t kReconcileMinIntervalUs = 5LL * 1000000; // 5 s
	const int64_t lastReconcile = _lastReconcileUs.load(std::memory_order_acquire);
	if (lastReconcile != 0 && esp_timer_get_time() - lastReconcile < kReconcileMinIntervalUs)
	{
		return;
	}
	_lastReconcileUs.store(esp_timer_get_time(), std::memory_order_release);

	// Claim the one-shot slot BEFORE the spawn so a second tick can't double-spawn the worker.
	_reconcileInFlight.store(true, std::memory_order_release);
	if (xTaskCreate(&TelephonyAnchorClient::reconcileTaskTrampoline, "tel_reconcile", 6144, this, 5, nullptr) != pdPASS)
	{
		// Rare error path (not the hot path): release the slot, else the watchdog wedges forever.
		ESP_LOGE(TAG, "tick: failed to spawn reconcile worker");
		_reconcileInFlight.store(false, std::memory_order_release);
	}
}

// One-shot worker: if _outboundActive has been stuck past the grace window, ask Telephony what is
// actually on the DN and clear the flag ONLY on definitive evidence the DN is empty. Off-SIP so
// the blocking GET is safe here.
void TelephonyAnchorClient::reconcileTaskTrampoline(void* arg)
{
	auto* self = static_cast<TelephonyAnchorClient*>(arg);

	std::string url;
	{
		std::lock_guard<std::mutex> lock(self->_mutex);
		url = self->_baseUrl + "/callcontrol/" + self->_sourceDn + "/participants";
	}

	ESP_LOGI(TAG, "reconcile watchdog: checking live participants on DN %s", self->_sourceDn.c_str());

	std::string body;
	int status = 0;
	const bool ok = self->httpGetBody(url, body, &status);

	// Only DEFINITIVE evidence — a clean 200 — acts. #100: build the set of legs the PBX currently
	// knows on our DN; any outbound-wedged slot (flag set, no media) whose own leg is ABSENT from
	// that set never materialized, so tear it down to reclaim the slot. A failed/timed-out/non-200
	// GET is "no evidence" and must NOT free anything (a transient failure must never become a false
	// all-clear that drops a real call).
	if (ok && status == 200)
	{
		std::vector<std::string> liveIds;
		cJSON* root = cJSON_Parse(body.c_str());
		if (root)
		{
			CJsonDeleter deleter{root};
			if (cJSON_IsArray(root))
			{
				cJSON* elem = nullptr;
				cJSON_ArrayForEach(elem, root)
				{
					std::string id = legIdOf(elem);
					if (!id.empty()) liveIds.push_back(id);
				}
			}
		}
		// Snapshot the wedged slots' own legs under the lock, then tear each absent one down (we
		// can't hold _mutex across stopMediaStreams). Bounded by the slot count — no heap on the path.
		std::string wedged[POCKETDIAL_MAX_ANCHOR_CALLS];
		int nWedged = 0;
		{
			std::lock_guard<std::mutex> lock(self->_mutex);
			for (auto& s : self->_calls)
			{
				if (s.participantId.empty()) continue;
				if (!s.outboundActive.load(std::memory_order_acquire)) continue;
				if (s.postLive.load(std::memory_order_acquire)) continue;
				bool live = false;
				for (const auto& id : liveIds) if (id == s.participantId) { live = true; break; }
				if (!live && nWedged < POCKETDIAL_MAX_ANCHOR_CALLS) wedged[nWedged++] = s.participantId;
			}
		}
		for (int i = 0; i < nWedged; ++i)
		{
			ESP_LOGI(TAG, "reconcile watchdog: leg %s absent from DN — tearing down wedged slot", wedged[i].c_str());
			self->stopMediaStreams(wedged[i]);   // frees the slot (clears outboundActive + sigPart)
		}
	}
	else
	{
		ESP_LOGW(TAG, "reconcile watchdog: GET inconclusive (ok=%d status=%d) — slots unchanged",
		         ok ? 1 : 0, status);
	}

	// Single exit: clear the one-shot slot so tick() can re-arm, THEN self-delete. vTaskDelete()
	// does not unwind the C++ stack, so this clear must be explicit here (not an RAII guard) — and
	// the only cJSON RAII above is confined to an inner scope that has already run.
	self->_reconcileInFlight.store(false, std::memory_order_release);
	vTaskDelete(nullptr);
}

// #107: one-shot worker spawned by tick() when the anchor is idle. Reopens the persistent
// POST handle so its cached TLS session RESUMES (abbreviated handshake) and Telephony issues a
// fresh ticket — extending validity so the next real call's /stream open also resumes. Runs
// off the SIP task because the open/close blocks on TLS I/O.
void TelephonyAnchorClient::rewarmTaskTrampoline(void* arg)
{
	auto* self = static_cast<TelephonyAnchorClient*>(arg);
	self->rewarmPostSession();
	// Single exit: release the one-shot slot so tick() can re-arm, then self-delete.
	self->_rewarmInFlight.store(false, std::memory_order_release);
	vTaskDelete(nullptr);
}

void TelephonyAnchorClient::rewarmPostSession()
{
	std::string baseUrl, sourceDn, token;
	{
		std::lock_guard<std::mutex> lock(_mutex);
		baseUrl  = _baseUrl;
		sourceDn = _sourceDn;
		token    = _accessToken;
	}
	if (baseUrl.empty())
	{
		return;   // unprovisioned / loopback — nothing to warm
	}

	// Benign same-host target: we only need the TLS handshake (which resumes the cached session);
	// the HTTP status is irrelevant. Kept as POST so startMediaStreams reuses the handle unchanged
	// (it re-points the URL to the call's /stream on the next call).
	const std::string url = baseUrl + "/callcontrol/" + sourceDn + "/participants";

	// #100: warm each slot's persistent POST session so even a CONCURRENT first-call burst resumes
	// its TLS instead of paying the S3's ~1s cold ECDHE. Slot 0 is primed even when cold (the
	// first idle→call path, as the single-call anchor always did); higher slots are only REFRESHED
	// if they already hold a resumable session — we don't preemptively burn cold handshakes on
	// slots a burst may never reach. Each slot is independent under its own postMutex; skip any with
	// a live audio stream (never disturb a call). Sequential — runs off the SIP task at idle.
	for (size_t i = 0; i < POCKETDIAL_MAX_ANCHOR_CALLS; ++i)
	{
		CallSlot& slot = _calls[i];
		std::lock_guard<std::mutex> postLock(slot.postMutex);
		if (slot.postLive.load(std::memory_order_acquire)) continue;   // call in progress on this slot
		if (slot.postClient == nullptr && i != 0) continue;            // don't cold-prime higher slots

		if (slot.postClient == nullptr)
		{
			// No handle yet (no call since boot): this open is a COLD handshake, but it primes the
			// session so the first real call resumes.
			slot.postClient = makeAuthedClient(url, HTTP_METHOD_POST, 1024, token);
			if (!slot.postClient)
			{
				ESP_LOGW(TAG, "rewarm: failed to create POST client (slot %d)", (int)i);
				continue;
			}
		}
		else
		{
			esp_http_client_set_url(slot.postClient, url.c_str());
			if (!token.empty())
			{
				const std::string authHeader = "Bearer " + token;
				esp_http_client_set_header(slot.postClient, "Authorization", authHeader.c_str());
			}
		}

		const int64_t t0 = esp_timer_get_time();
		esp_err_t err = esp_http_client_open(slot.postClient, 0);   // 0-length body: handshake only
		if (err != ESP_OK)
		{
			// Stale warm handle (server reaped the connection) or a cold failure: drop it so the
			// next heartbeat — or the next real call's retry path — rebuilds from clean.
			ESP_LOGW(TAG, "rewarm: POST open failed (%s, slot %d) — dropping handle", esp_err_to_name(err), (int)i);
			esp_http_client_cleanup(slot.postClient);
			slot.postClient = nullptr;
			continue;
		}
		// Drain headers + body so the connection is clean for the next reuse, then CLOSE but KEEP
		// the handle (its cached TLS session is the whole point). Do NOT touch postLive or the
		// call-path handshake telemetry — this is maintenance, not a call.
		(void)esp_http_client_fetch_headers(slot.postClient);
		const int status = esp_http_client_get_status_code(slot.postClient);
		char drain[256];
		while (esp_http_client_read(slot.postClient, drain, sizeof(drain)) > 0) { /* discard */ }
		esp_http_client_close(slot.postClient);

		const int64_t ms = (esp_timer_get_time() - t0) / 1000;
		ESP_LOGI(TAG, "rewarm: slot %d POST TLS session refreshed in %lld ms (status %d) -> %s",
		         (int)i, (long long)ms, status, (ms > 400) ? "FULL (was cold)" : "resumed");
	}
}

// #100: cold-prime EVERY slot's GET *and* POST TLS session after connect, so a cold-start concurrent
// burst RESUMES each per-call open instead of paying the S3's ~1s software ECDHE per stream. We only
// need the TLS HANDSHAKE to complete (the HTTP status is irrelevant) — afterwards CLOSE but KEEP each
// handle so its cached session resumes on the real call. Sequential + off the SIP task (16 cold
// handshakes ≈ ~16 s at idle); spawned once from start().
void TelephonyAnchorClient::prewarmTaskTrampoline(void* arg)
{
	auto* self = static_cast<TelephonyAnchorClient*>(arg);
	self->prewarmAllSlots();
	vTaskDeleteWithCaps(nullptr);
}

void TelephonyAnchorClient::prewarmAllSlots()
{
	std::string baseUrl, sourceDn, token;
	{
		std::lock_guard<std::mutex> lock(_mutex);
		baseUrl  = _baseUrl;
		sourceDn = _sourceDn;
		token    = _accessToken;
	}
	if (baseUrl.empty()) return;   // unprovisioned / loopback
	// Benign same-host target: only the handshake matters (GET → participant list 200; POST → 405).
	const std::string url = baseUrl + "/callcontrol/" + sourceDn + "/participants";

	auto warmHandle = [&](esp_http_client_handle_t& h, esp_http_client_method_t method) -> bool {
		if (!_running.load(std::memory_order_acquire)) return false;
		if (!h) h = makeAuthedClient(url, method, 1024, token);
		if (!h) return false;
		const int64_t t0 = esp_timer_get_time();
		if (esp_http_client_open(h, 0) != ESP_OK)
		{
			esp_http_client_cleanup(h); h = nullptr; return false;
		}
		(void)esp_http_client_fetch_headers(h);
		char d[256];
		while (esp_http_client_read(h, d, sizeof(d)) > 0) { /* discard */ }
		esp_http_client_close(h);   // KEEP the handle + its now-cached session
		const int64_t ms = (esp_timer_get_time() - t0) / 1000;
		ESP_LOGI(TAG, "prewarm: TLS session primed in %lld ms (%s)", (long long)ms, (ms > 400) ? "cold" : "resumed");
		return true;
	};

	int warmed = 0;
	for (auto& slot : _calls)
	{
		if (!_running.load(std::memory_order_acquire)) break;
		// Never disturb a slot that's mid-call (a real call grabbed it during prewarm).
		bool busy = false;
		{
			std::lock_guard<std::mutex> lock(_mutex);
			busy = !slot.participantId.empty();
		}
		if (busy) continue;

		// POST only: the POST handle resumes via HTTP keep-alive across calls (clean close). The GET
		// stream can't be kept warm the same way — its fast teardown shut​down()s the socket to
		// unblock the long-poll read, which kills the keep-alive connection, so a per-call GET open
		// pays a fresh handshake regardless. Warming it here would just leak the handle (runRxLoop
		// creates a fresh GET client). Warming GET needs a timeout-based rx teardown (follow-up).
		{
			std::lock_guard<std::mutex> pl(slot.postMutex);
			if (!slot.postLive.load(std::memory_order_acquire) && warmHandle(slot.postClient, HTTP_METHOD_POST)) ++warmed;
		}
	}
	ESP_LOGI(TAG, "prewarm: %d/%d slots' POST TLS sessions primed (resumable)", warmed, POCKETDIAL_MAX_ANCHOR_CALLS);
}

// Issue #65 (L-1): one-shot worker that reclaims leaked GET sockets by cycling the
// whole anchor. stop() tears down the WS + control + media clients and frees every
// socket it still OWNS; the leaked _getClient handles cannot be closed (their mutex is
// poisoned), but a full stop()/start() drops the anchor's live socket footprint to
// zero and rebuilds it clean, so the pool recovers headroom. Runs off the SIP task
// because stop()/start() block on TLS teardown/handshake.
void TelephonyAnchorClient::restartTaskTrampoline(void* arg)
{
	auto* self = static_cast<TelephonyAnchorClient*>(arg);

	ESP_LOGW(TAG, "anchor restart: reclaiming socket pool after %d leaked GET handle(s)",
	         self->_leakedGetClients.load(std::memory_order_relaxed));

	// Clear the request BEFORE the cycle so a leak that happens during/after the
	// restart re-arms the watchdog instead of being swallowed.
	self->_restartRequested.store(false, std::memory_order_release);

	// stop() nulls _eventCb/_audioCb (they are installed once at boot by the engine
	// wiring and never re-installed by start()). Snapshot them under _mutex and
	// re-register after stop() so the reconnected anchor still delivers Incoming events
	// and inbound audio — otherwise the restart would leave the anchor deaf.
	EventCallback   savedEventCb;
	AudioRxCallback savedAudioCb;
	{
		std::lock_guard<std::mutex> lock(self->_mutex);
		savedEventCb = self->_eventCb;
		savedAudioCb = self->_audioCb;
	}

	self->stop();
	// Reset the leak tally: stop() has released everything the anchor owned, so the
	// previously-leaked handles are the OS's problem now and the fresh session starts
	// from a clean count. (A still-poisoned mutex would re-leak and re-trip the gate.)
	self->_leakedGetClients.store(0, std::memory_order_release);

	// Re-install the callbacks before start() so the new WS session is wired up.
	self->setEventCallback(savedEventCb);
	self->registerAudioRxCallback(savedAudioCb);

	if (!self->start())
	{
		ESP_LOGE(TAG, "anchor restart: start() failed — will retry on the next reconnect cycle");
	}
	else
	{
		ESP_LOGI(TAG, "anchor restart: complete, socket pool reclaimed");
	}

	// Clear the in-flight gate LAST so tick() can spawn a future restart if needed.
	self->_restartInFlight.store(false, std::memory_order_release);
	vTaskDelete(nullptr);
}

esp_http_client_handle_t TelephonyAnchorClient::makeAuthedClient(const std::string& url, esp_http_client_method_t method, int txBufSize, const std::string& token)
{
	esp_http_client_config_t config = {};
	config.url = url.c_str();
	config.method = method;
	config.crt_bundle_attach = esp_crt_bundle_attach;
	config.buffer_size = 4096;
	config.buffer_size_tx = txBufSize;
	config.timeout_ms = 2000; // 2 seconds timeout to bound blocking calls
	// #93 — TLS session resumption + warm connection reuse. The ESP32-S3 has NO ECC
	// accelerator (SOC_ECC_SUPPORTED is unset), so the ECDHE in every full TLS handshake
	// is software-bound (~0.5-1 s) and cannot be sped up in hardware. The only lever is to
	// AVOID the full handshake: keep_alive_enable holds the TCP+TLS connection open for
	// reuse, and save_client_session caches the TLS session ticket so a reconnect resumes
	// (abbreviated handshake, ~1 RTT) instead of re-doing the ECDHE. Paired with
	// warmCtrlConnection() (which establishes the persistent _ctrlClient at init), the
	// first dial reuses/resumes the already-warmed control session rather than cold-handshaking.
	// Requires CONFIG_ESP_TLS_CLIENT_SESSION_TICKETS + CONFIG_MBEDTLS_CLIENT_SSL_SESSION_TICKETS.
	config.keep_alive_enable  = true;
	config.save_client_session = true;

	esp_http_client_handle_t client = esp_http_client_init(&config);
	if (!client)
	{
		return nullptr;
	}

	if (!token.empty())
	{
		std::string authHeader = "Bearer " + token;
		esp_http_client_set_header(client, "Authorization", authHeader.c_str());
	}

	return client;
}

bool TelephonyAnchorClient::performAuthedRequest(esp_http_client_handle_t client, int* statusCodeOut)
{
	esp_err_t err = esp_http_client_perform(client);
	int status = -1;
	if (err == ESP_OK)
	{
		status = esp_http_client_get_status_code(client);
		if (statusCodeOut)
		{
			*statusCodeOut = status;
		}
		return (status >= 200 && status < 300);
	}
	else
	{
		ESP_LOGE(TAG, "HTTP perform failed: %s", esp_err_to_name(err));
		if (statusCodeOut)
		{
			*statusCodeOut = -1;
		}
		return false;
	}
}

bool TelephonyAnchorClient::performCtrl(const std::string& url, const char* contentType, const std::string& body, int* statusCodeOut)
{
	std::string token;
	{
		std::lock_guard<std::mutex> lock(_mutex);
		token = _accessToken;
	}

	std::lock_guard<std::mutex> ctrlLock(_ctrlMutex);

	// Two attempts: the first may ride a connection the server idled out, in
	// which case perform() fails; the second goes out on a fresh handle, which
	// is exactly what every request paid before this connection was persistent.
	for (int attempt = 0; attempt < 2; ++attempt)
	{
		if (!_ctrlClient)
		{
			_ctrlClient = makeAuthedClient(url, HTTP_METHOD_POST, 1024, token);
			if (!_ctrlClient)
			{
				return false;
			}
		}
		else
		{
			esp_http_client_set_url(_ctrlClient, url.c_str());
			esp_http_client_set_method(_ctrlClient, HTTP_METHOD_POST);
			// Token may have rotated since the handle was created.
			std::string authHeader = "Bearer " + token;
			esp_http_client_set_header(_ctrlClient, "Authorization", authHeader.c_str());
		}

		if (contentType)
		{
			esp_http_client_set_header(_ctrlClient, "Content-Type", contentType);
		}
		esp_http_client_set_post_field(_ctrlClient, body.c_str(), body.length());

		esp_err_t err = esp_http_client_perform(_ctrlClient);
		if (err == ESP_OK)
		{
			int status = esp_http_client_get_status_code(_ctrlClient);
			if (statusCodeOut)
			{
				*statusCodeOut = status;
			}
			return (status >= 200 && status < 300);
		}

		ESP_LOGW(TAG, "Control request failed (%s)%s", esp_err_to_name(err),
		         attempt == 0 ? " — reconnecting" : "");
		esp_http_client_cleanup(_ctrlClient);
		_ctrlClient = nullptr;
	}

	if (statusCodeOut)
	{
		*statusCodeOut = -1;
	}
	return false;
}

void TelephonyAnchorClient::warmCtrlConnection()
{
	// Establish the control-plane TLS session ahead of the first command so a
	// makecall right after dialing doesn't pay the handshake. A POST to the DN
	// root is a no-op command-wise (Telephony answers 4xx) but completes the TLS+TCP
	// setup that perform() will then reuse.
	std::string url;
	{
		std::lock_guard<std::mutex> lock(_mutex);
		url = _baseUrl + "/callcontrol/" + _sourceDn;
	}
	int status = 0;
	performCtrl(url, nullptr, "", &status);
	ESP_LOGI(TAG, "Control connection pre-warmed (HTTP %d)", status);
}

void TelephonyAnchorClient::warmStatusConnection()
{
	// Prime the persistent status-GET session (getLegStatus/reconcileParticipantId/
	// getParticipantCaller/resolveDevice all share it) ahead of the first real call, same
	// rationale as warmCtrlConnection: pay the cold ECDHE at boot, not mid-call.
	std::string url;
	{
		std::lock_guard<std::mutex> lock(_mutex);
		url = _baseUrl + "/callcontrol/" + _sourceDn + "/participants";
	}
	std::string body;
	int status = 0;
	httpGetBody(url, body, &status);
	ESP_LOGI(TAG, "Status connection pre-warmed (HTTP %d)", status);
}

void TelephonyAnchorClient::closeCtrlClient()
{
	std::lock_guard<std::mutex> ctrlLock(_ctrlMutex);
	if (_ctrlClient)
	{
		esp_http_client_cleanup(_ctrlClient);
		_ctrlClient = nullptr;
	}
}

void TelephonyAnchorClient::closeStatusClient()
{
	std::lock_guard<std::mutex> statusLock(_statusMutex);
	if (_statusClient)
	{
		esp_http_client_cleanup(_statusClient);
		_statusClient = nullptr;
	}
}

void TelephonyAnchorClient::closePostClient()
{
	// Free EVERY slot's persistent warm POST handle (and any surviving GET handle). stopMediaStreams
	// keeps the warm POST alive between calls for TLS resumption; only a full anchor teardown frees
	// it. #100: iterate all slots.
	for (auto& slot : _calls)
	{
		{
			std::lock_guard<std::mutex> postLock(slot.postMutex);
			if (slot.postClient)
			{
				if (slot.postLive.load(std::memory_order_acquire))
				{
					esp_http_client_close(slot.postClient);
				}
				esp_http_client_cleanup(slot.postClient);
				slot.postClient = nullptr;
				slot.postLive.store(false, std::memory_order_release);
			}
		}
		{
			std::lock_guard<std::mutex> getLock(slot.getMutex);
			if (slot.getClient)
			{
				esp_http_client_close(slot.getClient);
				esp_http_client_cleanup(slot.getClient);
				slot.getClient = nullptr;
			}
		}
	}
}

void TelephonyAnchorClient::stopAllMediaStreams()
{
	// Snapshot the active participant ids under _mutex (fixed array, no heap), then stop each slot
	// (stopMediaStreams takes _mutex itself, so we can't hold it across the calls). Used by
	// shutdown and the WS-disconnect handler.
	std::string parts[POCKETDIAL_MAX_ANCHOR_CALLS];
	int n = 0;
	{
		std::lock_guard<std::mutex> lock(_mutex);
		for (auto& s : _calls)
		{
			if (!s.participantId.empty() && n < POCKETDIAL_MAX_ANCHOR_CALLS) parts[n++] = s.participantId;
		}
	}
	for (int i = 0; i < n; ++i)
	{
		stopMediaStreams(parts[i]);
	}
}

bool TelephonyAnchorClient::readJsonStringField(esp_http_client_handle_t client, const std::string& field, std::string& out)
{
	std::vector<char> buffer;
	char tempBuf[512];
	int readBytes = 0;
	while ((readBytes = esp_http_client_read(client, tempBuf, sizeof(tempBuf))) > 0)
	{
		buffer.insert(buffer.end(), tempBuf, tempBuf + readBytes);
	}
	if (readBytes < 0)
	{
		ESP_LOGE(TAG, "HTTP read error: %d", readBytes);
		return false;
	}
	if (buffer.empty())
	{
		return false;
	}
	buffer.push_back('\0');
	cJSON* root = cJSON_Parse(buffer.data());
	if (!root)
	{
		ESP_LOGE(TAG, "Failed to parse JSON response");
		return false;
	}
	bool found = false;
	cJSON* item = cJSON_GetObjectItem(root, field.c_str());
	if (item && item->valuestring)
	{
		out = item->valuestring;
		found = true;
	}
	cJSON_Delete(root);
	return found;
}

void TelephonyAnchorClient::wsEventTrampoline(void* handlerArgs, esp_event_base_t /*base*/,
                                           int32_t eventId, void* eventData)
{
	auto* self = static_cast<TelephonyAnchorClient*>(handlerArgs);
	self->handleWsEvent(eventId, eventData);
}

// ── #43: WS event worker pool ────────────────────────────────────────────────
bool TelephonyAnchorClient::startWsWorkers()
{
	if (_wsWorkQueue) return true;   // idempotent (restart path reuses)
	if (!_wsWorkerDoneSem)
	{
		_wsWorkerDoneSem = xSemaphoreCreateCounting(kWsWorkers, 0);
		if (!_wsWorkerDoneSem) { ESP_LOGE(TAG, "startWsWorkers: sem create failed"); return false; }
	}
	_wsWorkQueue = xQueueCreate(kWsQueueDepth, sizeof(WsWorkItem*));
	if (!_wsWorkQueue)
	{
		ESP_LOGE(TAG, "startWsWorkers: xQueueCreate failed");
		return false;
	}
	_wsWorkersRun.store(true, std::memory_order_release);
	for (int i = 0; i < kWsWorkers; ++i)
	{
		// 12288 stack: the worker runs getLegStatus()+startMediaStreams() — the same blocking
		// TLS HTTP the WS task used to carry. Unpinned so the scheduler keeps it off the SIP core.
		// #100: stack in PSRAM (WithCaps) — with kWsWorkers>1 for concurrent setup, N*12 KB would
		// otherwise eat internal RAM. TLS I/O only (no flash writes) → PSRAM-safe; self-deletes WithCaps.
		if (xTaskCreateWithCaps(&TelephonyAnchorClient::wsWorkerTrampoline, "tel_wsw", 12288, this, 4,
		                &_wsWorkerHandles[i], PD_TASK_STACK_CAPS) != pdPASS)
		{
			ESP_LOGE(TAG, "startWsWorkers: xTaskCreate worker %d failed (heap?)", i);
			_wsWorkerHandles[i] = nullptr;
			// Worker won't run -> never gives the done-sem; pre-give so stopWsWorkers()'s
			// per-worker join doesn't block on a worker that never started.
			xSemaphoreGive(_wsWorkerDoneSem);
		}
	}
	return true;
}

void TelephonyAnchorClient::stopWsWorkers()
{
	if (!_wsWorkQueue) return;
	_wsWorkersRun.store(false, std::memory_order_release);
	// Wake each worker with a nullptr sentinel so it leaves xQueueReceive and self-deletes.
	for (int i = 0; i < kWsWorkers; ++i)
	{
		WsWorkItem* sentinel = nullptr;
		xQueueSend(_wsWorkQueue, &sentinel, 0);
	}
	// Wait for EVERY worker to signal done (it gives the sem only after it has left
	// runWsWorker()/xQueueReceive), so vQueueDelete() below can't race a blocked receive.
	// 8 s/worker is generous — a worker's longest unit is getLegStatus()/startMediaStreams()
	// (bounded HTTP timeouts). On the failure-to-spawn path the sem was pre-given.
	for (int i = 0; i < kWsWorkers; ++i)
	{
		if (_wsWorkerDoneSem) xSemaphoreTake(_wsWorkerDoneSem, pdMS_TO_TICKS(8000));
	}
	// Drain leftover queued items so they don't leak.
	WsWorkItem* leftover = nullptr;
	while (xQueueReceive(_wsWorkQueue, &leftover, 0) == pdTRUE) delete leftover;
	vQueueDelete(_wsWorkQueue);
	_wsWorkQueue = nullptr;
	for (int i = 0; i < kWsWorkers; ++i) _wsWorkerHandles[i] = nullptr;
}

bool TelephonyAnchorClient::enqueueWsWork(WsWorkItem* item)
{
	if (!item) return false;
	if (!_wsWorkQueue || xQueueSend(_wsWorkQueue, &item, 0) != pdTRUE)
	{
		// Queue not ready or full — drop it (Telephony repeats the upset every ~750 ms). No leak.
		delete item;
		return false;
	}
	return true;
}

void TelephonyAnchorClient::wsWorkerTrampoline(void* arg)
{
	auto* self = static_cast<TelephonyAnchorClient*>(arg);
	self->runWsWorker();
	if (self->_wsWorkerDoneSem) xSemaphoreGive(self->_wsWorkerDoneSem);   // released BEFORE delete
	vTaskDeleteWithCaps(nullptr);   // #100: created WithCaps(PSRAM) — reclaim the PSRAM stack/TCB
}

void TelephonyAnchorClient::runWsWorker()
{
	// Capture the queue locally: stopWsWorkers() nulls the _wsWorkQueue member, but only
	// AFTER it has joined us via the done-sem, so the handle stays valid for our lifetime.
	QueueHandle_t q = _wsWorkQueue;
	if (!q) return;
	for (;;)
	{
		WsWorkItem* item = nullptr;
		if (xQueueReceive(q, &item, portMAX_DELAY) != pdTRUE) continue;
		if (!item)   // nullptr sentinel from stopWsWorkers()
		{
			if (!_wsWorkersRun.load(std::memory_order_acquire)) return;
			continue;
		}
		if (_wsWorkersRun.load(std::memory_order_acquire)) processWsWork(*item);
		delete item;
	}
}

// The blocking body, lifted verbatim from the old inline handler so behaviour is unchanged —
// only the EXECUTION CONTEXT moved off the WS event task (#43).
void TelephonyAnchorClient::processWsWork(const WsWorkItem& w)
{
	if (!_running.load(std::memory_order_acquire)) return;   // bail during teardown

	EventCallback evCb;
	{
		std::lock_guard<std::mutex> lock(_mutex);
		evCb = _eventCb;
	}

	if (w.kind == WsWork::Remove)
	{
		// #100: map the removed participant to a slot. Telephony may name our own leg or (issue #40) the
		// far leg; match by id first, else fall back to the sole active call (single-leg DN). The
		// teardown frees the slot (idempotent via its per-slot tearingDown gate); freeSlotLocked
		// also clears its inboundSignaledPartId so a recycled partId can re-announce next time.
		std::string dropLeg;
		{
			std::lock_guard<std::mutex> lock(_mutex);
			CallSlot* s = slotForLocked(w.partId);
			if (!s)
			{
				// Far-leg Remove: Telephony names the external party's participant id, not ours.
				// Match against each slot's recorded far-leg id so N-call teardown works.
				for (auto& c : _calls)
					if (!c.participantId.empty() && c.farPartId == w.partId) { s = &c; break; }
			}
			if (s)
			{
				dropLeg = s->participantId;
			}
			else
			{
				CallSlot* only = nullptr; int active = 0;
				for (auto& c : _calls) if (!c.participantId.empty()) { ++active; only = &c; }
				if (active == 1) dropLeg = only->participantId;
			}
		}
		if (!dropLeg.empty())
		{
			stopMediaStreams(dropLeg);
			if (evCb)
			{
				CallEvent ev{CallEvent::Dropped, dropLeg, "", ""};
				evCb(ev);
			}
		}
		else
		{
			ESP_LOGW(TAG, "WS Remove for %s matched no slot", w.partId.c_str());
		}
		return;
	}

	// (Upset) #100: RE-RESOLVE the control leg at PROCESS time. handleWsEvent resolves controlLeg at
	// ENQUEUE time, but under a concurrent burst an early upset for a leg can be queued BEFORE
	// makecall finishes creating that leg's slot — the enqueue-time heuristic then maps it to a
	// DIFFERENT in-flight leg, and once the real leg goes Connected Telephony stops repeating the upset so
	// the stale mapping never self-corrects and that call never bridges (the N>=4 mis-map). By
	// process time the slots are stable: if the surfaced partId now owns a slot, IT is the control
	// leg; otherwise keep handleWsEvent's far-leg/inbound mapping (issue #40). A slot that is
	// outboundActive is one of OUR outbound calls; anything else is an INBOUND PSTN call.
	//
	// The whole body below runs inside a single-flight loop keyed on the slot's upsetInFlight/
	// upsetPending pair (set at enqueue time in handleWsEvent). A repeat upset that lands while
	// this worker is mid status-check does NOT spawn a second worker — it just flags upsetPending,
	// and the tail of this loop rechecks once more before releasing the flight flag. This is what
	// collapses "Telephony repeats the upset every ~750ms" into ONE getLegStatus()/startMediaStreams()
	// pass instead of up to kWsWorkers concurrent cold-handshake passes for the same still-pending
	// call, while still catching a Dialing->Connected transition that arrives mid-check (a blanket
	// drop-the-repeat gate would silently lose that transition instead).
	std::string controlLeg = w.controlLeg;
	for (;;)
	{
		bool outbound = false;
		{
			std::lock_guard<std::mutex> lock(_mutex);
			if (slotForLocked(w.partId)) controlLeg = w.partId;
			CallSlot* s = slotForLocked(controlLeg);
			outbound = s && s->outboundActive.load(std::memory_order_acquire);
		}

		if (!outbound)
		{
			// INBOUND. A Telephony ROUTE POINT connects the PSTN leg immediately, so the very first upset is
			// already 'Connected' — we must NOT fall into the outbound "Answered" path (that bridges
			// dead air to a phone that never rang). Announce ONCE (per-slot flag) so the engine rings
			// the local extensions, then pre-warm BOTH media streams during ringing so audio cuts
			// through the instant the handset answers. No audio is written until a handset bridges
			// (MediaBridge), so Telephony just sees an idle stream meanwhile. answerCall() opens media when a
			// local handset answers, so there is exactly one inbound media starter and no race here.
			bool announce = false;
			{
				std::lock_guard<std::mutex> lock(_mutex);
				// Find-or-claim the inbound slot so the announce-once flag lives on it (keyed by the
				// surfaced leg). All slots busy => no slot => no announce (graceful at capacity).
				CallSlot* s = allocSlotLocked(controlLeg);
				if (s)
				{
					announce = (s->inboundSignaledPartId != controlLeg);
					if (announce) s->inboundSignaledPartId = controlLeg;
				}
			}
			if (announce)
			{
				// Caller ID: the WS event's attached_data is often null on a route point, so fall
				// back to the participant resource (party_caller_id/name) for a real number/name
				// instead of the generic "PSTN" label. Blocking GET — fine on this worker task.
				std::string caller = w.callerId;
				if (caller.empty()) caller = getParticipantCaller(controlLeg);
				ESP_LOGI(TAG, "Inbound call on DN %s: participant %s caller '%s'",
				         _sourceDn.c_str(), controlLeg.c_str(), caller.c_str());
				if (evCb)
				{
					CallEvent ev{CallEvent::Incoming, controlLeg, "", caller};
					evCb(ev);
				}
			}
			startMediaStreams(controlLeg);
		}
		else
		{
			// OUTBOUND. Re-apply the throttle the original code ran synchronously: Telephony repeats the
			// upset every ~750 ms, and with the work deferred several can queue before our first
			// startMediaStreams() completes. Skip only once THIS slot is fully up (POST live AND
			// Answered already fired) — media is pre-warmed during dialing, so postLive alone is true
			// BEFORE connect and using it as the sole skip would swallow the Connected->Answered
			// transition.
			bool fullyUp = false;
			{
				std::lock_guard<std::mutex> lock(_mutex);
				CallSlot* s = slotForLocked(controlLeg);
				fullyUp = s && s->postLive.load(std::memory_order_acquire) &&
				          s->outboundAnswered.load(std::memory_order_acquire);
			}

			if (!fullyUp)
			{
				// Authoritative status from the LIST (GET /participants -> find leg), never
				// getParticipantStatus(id) which 403s for a non-controlled leg (issue #40).
				std::string statusStr = getLegStatus(controlLeg);
				ESP_LOGI(TAG, "Upset %s -> control leg %s status '%s'", w.partId.c_str(), controlLeg.c_str(), statusStr.c_str());

				// Helper to read THIS slot's postLive (slot pointer stays valid — fixed array — but
				// re-fetch the flag rather than caching across the blocking calls below).
				auto slotPostLive = [this](const std::string& leg) {
					std::lock_guard<std::mutex> lock(_mutex);
					CallSlot* s = slotForLocked(leg);
					return s && s->postLive.load(std::memory_order_acquire);
				};

				if (statusStr == "Connected")
				{
					// The PSTN leg answered. Media is usually already up from the dialing pre-warm;
					// open it now as a fallback if a pre-answer stream open was rejected. Then fire
					// Answered EXACTLY ONCE (the per-slot one-shot decouples the answer signal from
					// "media is streaming", which pre-warm makes true early). Control + media key off
					// OUR leg (controlLeg).
					bool live = slotPostLive(controlLeg);
					if (!live)
					{
						startMediaStreams(controlLeg);
						live = slotPostLive(controlLeg);
					}
					if (live)
					{
						bool fire = false;
						{
							std::lock_guard<std::mutex> lock(_mutex);
							CallSlot* s = slotForLocked(controlLeg);
							if (s)
							{
								fire = !s->outboundAnswered.exchange(true, std::memory_order_acq_rel);
								// Record far-leg id so a Remove naming the external party maps back to us.
								if (s->farPartId.empty() && w.partId != controlLeg)
									s->farPartId = w.partId;
							}
						}
						if (fire && evCb)
						{
							CallEvent ev{CallEvent::Answered, controlLeg, "", ""};
							evCb(ev);
						}
					}
					else
					{
						ESP_LOGE(TAG, "Failed to start media streams for participant %s", controlLeg.c_str());
						stopMediaStreams(controlLeg);
					}
				}
				else
				{
					// Our own OUTBOUND leg, not yet Connected (dialing/ringing): pre-warm the GET
					// stream ONLY. Telephony streams ringback/early-media on the GET during dialing, so it
					// works pre-connect and the Telephony->handset direction cuts through at answer. But
					// Telephony does NOT route a POST (device->Telephony) stream opened before the leg is
					// Connected — it accepts the writes then silently drops them (hardware-confirmed).
					// So the POST is opened in the Connected branch above, to the now-Connected leg.
					// (Inbound differs: its route-point leg is already Connected during the local
					// ring, so the inbound gate pre-warms BOTH streams there.)
					startRxIfNeeded(controlLeg);
				}
			}
		}

		// Single-flight tail: a repeat that arrived while the pass above was running set
		// upsetPending instead of spawning a new worker. Recheck once more (cheap: getLegStatus on a
		// now-warm control connection) rather than waiting up to ~750ms for the next natural repeat —
		// that's how a Connected transition that lands mid-check still gets picked up immediately.
		CallSlot* s = nullptr;
		{
			std::lock_guard<std::mutex> lock(_mutex);
			s = slotForLocked(controlLeg);
		}
		if (!s) break;   // slot vanished (teardown race) — nothing left to flush
		if (s->upsetPending.exchange(false, std::memory_order_acq_rel))
		{
			continue;
		}
		s->upsetInFlight.store(false, std::memory_order_release);
		break;
	}
}

void TelephonyAnchorClient::handleWsEvent(int32_t eventId, void* eventData)
{
	auto* data = static_cast<esp_websocket_event_data_t*>(eventData);

	switch (eventId)
	{
		case WEBSOCKET_EVENT_CONNECTED:
			ESP_LOGI(TAG, "Control channel: Websocket connected");
			_connected.store(true, std::memory_order_release);
			break;

		case WEBSOCKET_EVENT_DISCONNECTED:
			ESP_LOGW(TAG, "Control channel: Websocket disconnected");
			_connected.store(false, std::memory_order_release);
			{
				// A device registration flap can invalidate the cached device_id — drop it so the
				// next makeCall re-resolves rather than POSTing to a stale /devices/{id}/makecall.
				std::lock_guard<std::mutex> lock(_mutex);
				_deviceId.clear();
			}
			stopAllMediaStreams();   // #100: drop every active call slot on WS loss
			requestRestartIfTokenStale();   // #336
			break;

		// Issue #336: previously unhandled (fell to `default: break`) — this is the event
		// the esp_websocket_client fires on EVERY failed auto-reconnect attempt, not just
		// the first disconnect, so it is the actual repeat-offender in the stuck-401 loop
		// (DISCONNECTED fires once; ERROR fires every 5 s after, forever, once the token
		// is stale). Same check as DISCONNECTED, for the same reason.
		case WEBSOCKET_EVENT_ERROR:
			requestRestartIfTokenStale();   // #336
			break;

		case WEBSOCKET_EVENT_DATA:
			// Teardown gate: once stop()/disable has cleared _running, ignore further frames so a
			// late upsert cannot prime a new rx task (startRxIfNeeded) against a tearing-down client.
			if (!_running.load(std::memory_order_acquire)) break;
			// DIAGNOSTIC: dump every WS data frame raw, before any filtering, so we
			// can see exactly what Telephony pushes on ring/answer/hangup. op_code 0x01=text,
			// 0x02=binary, 0x08=close, 0x09=ping, 0x0A=pong, 0x00=continuation.
			ESP_LOGD(TAG, "WS frame: op=0x%02x len=%d off=%d total=%d", data->op_code,
			         data->data_len, data->payload_offset, data->payload_len);
			if (data->op_code == 0x01 && data->data_ptr != nullptr && data->data_len > 0)
			{
				std::string rawDump(data->data_ptr, data->data_len);
				ESP_LOGD(TAG, "WS payload: %s", rawDump.c_str());   // #100: ESP_LOGD — full-JSON dump flooded UART at multi-call scale
			}

			if (data->op_code == 0x01 && data->data_ptr != nullptr && data->data_len > 0)
			{
				// Received text data from WSS
				std::string payload(data->data_ptr, data->data_len);
				cJSON* root = cJSON_Parse(payload.c_str());
				if (!root) break;
				CJsonDeleter deleter{root};

				cJSON* eventObj = cJSON_GetObjectItem(root, "event");
				if (eventObj)
				{
					cJSON* evType = cJSON_GetObjectItem(eventObj, "event_type");
					cJSON* entity = cJSON_GetObjectItem(eventObj, "entity");

					if (cJSON_IsNumber(evType) && entity && entity->valuestring)
					{
						int evTypeNum = evType->valueint;
						std::string entityStr = entity->valuestring;

						// Parse entity path to verify DN and participantId:
						// /callcontrol/{dn}/participants/{id}. The tokenizer +
						// shape gate live in TelephonyAnchorLogic.hpp so the parse
						// is host-unit-tested (issue #49).
						telephony::ParticipantEntity ent = telephony::parseParticipantEntity(entityStr);
						if (ent.valid)
						{
							std::string dn = ent.dn;
							std::string partId = ent.participantId;

							if (dn == _sourceDn)
							{
								EventCallback evCb;
								{
									std::lock_guard<std::mutex> lock(_mutex);
									evCb = _eventCb;
								}

								if (evTypeNum == TEL_EV_UPSET)
								{
									// #100: map the surfaced participant to the leg(s) WE control. Telephony
									// repeats the Upset every ~750ms and may surface either our OWN leg
									// (result.id) or, for outbound, the FAR leg — on which a specific-id
									// GET/drop 403s (issue #40). Mapping rules:
									//   • partId matches a slot          -> that slot's own leg (in/outbound)
									//   • no match, 0 outbound in flight -> INBOUND; control leg = partId
									//   • no match, 1 outbound in flight -> that call's own leg (its far leg)
									//   • no match, >=2 in flight        -> ambiguous; re-check each (self-correcting)
									// While an outbound makecall is mid-resolve (_outboundPending>0) an
									// unmatched upset is treated as a pending far leg and IGNORED — a repeat
									// upset drives it once the slot is keyed, so an early upset can't false-ring.
									std::string controlLegs[POCKETDIAL_MAX_ANCHOR_CALLS];
									int nLegs = 0;
									{
										std::lock_guard<std::mutex> lock(_mutex);
										CallSlot* s = slotForLocked(partId);
										if (s)
										{
											controlLegs[nLegs++] = partId;
										}
										else
										{
											std::string inflight[POCKETDIAL_MAX_ANCHOR_CALLS];
											int nin = 0;
											for (auto& c : _calls)
											{
												if (!c.participantId.empty() &&
												    c.outboundActive.load(std::memory_order_acquire) &&
												    !c.outboundAnswered.load(std::memory_order_acquire))
													inflight[nin++] = c.participantId;
											}
											const int pending = _outboundPending.load(std::memory_order_acquire);
											if (nin == 0)
											{
												// No resolved outbound leg. If a makecall is mid-resolve, this
												// is its (far) leg — ignore; otherwise it's a new inbound call.
												if (pending == 0) controlLegs[nLegs++] = partId;
											}
											else if (nin == 1 && pending == 0)
											{
												controlLegs[nLegs++] = inflight[0];
											}
											else
											{
												// Ambiguous: re-check every resolved in-flight leg (their own
												// status GET is authoritative; a still-pending leg waits for a
												// repeat upset once it's keyed).
												for (int i = 0; i < nin; ++i) controlLegs[nLegs++] = inflight[i];
											}
										}
									}
									if (nLegs == 0) break;   // ignored (pending far leg / all-busy)

									// Best-effort caller id (cheap, JSON-only) for an inbound ring's From display.
									std::string callerId;
									cJSON* attached = cJSON_GetObjectItem(eventObj, "attached_data");
									if (attached)
									{
										for (const char* k : { "caller_id", "party_caller_id", "callerid", "caller_number" })
										{
											cJSON* c = cJSON_GetObjectItem(attached, k);
											if (c && c->valuestring && c->valuestring[0]) { callerId = c->valuestring; break; }
										}
									}

									for (int i = 0; i < nLegs; ++i)
									{
										const std::string& controlLeg = controlLegs[i];
										// Throttle: skip an upset that's a no-op (this slot fully up). Media is
										// pre-warmed during dialing, so postLive alone goes true BEFORE connect —
										// for OUTBOUND keep letting upserts through until Answered fires, or the
										// Connected upset is dropped and the handset rings forever. A not-yet-
										// existing inbound slot is never "fully up", so it always enqueues.
										bool alreadyQueued = false;
										{
											std::lock_guard<std::mutex> lock(_mutex);
											CallSlot* s = slotForLocked(controlLeg);
											if (s && s->postLive.load(std::memory_order_acquire) &&
											    (!s->outboundActive.load(std::memory_order_acquire) ||
											     s->outboundAnswered.load(std::memory_order_acquire)))
											{
												continue;   // already fully up
											}
											// Single-flight per slot: Telephony repeats an unresolved upset every ~750ms,
											// and without this gate each repeat spawned its OWN worker — with
											// kWsWorkers==POCKETDIAL_MAX_ANCHOR_CALLS, up to 4 running concurrently,
											// each paying its own cold getLegStatus() handshake for the SAME
											// still-pending call. If a worker is already resolving this leg, don't
											// spawn a second one; flag upsetPending so the in-flight worker rechecks
											// once more after it finishes (processWsWork), so a Dialing->Connected
											// transition landing mid-check is coalesced, never dropped.
											if (s)
											{
												if (s->upsetInFlight.exchange(true, std::memory_order_acq_rel))
												{
													s->upsetPending.store(true, std::memory_order_release);
													alreadyQueued = true;
												}
											}
										}
										if (alreadyQueued) continue;
										// #43: the status check + media start are blocking TLS HTTP — hand
										// them to the worker pool so the WS event task stays free for PINGs.
										// placement new(nothrow) returns an initialized pointer; cppcheck misparses it.
										// cppcheck-suppress legacyUninitvar
										auto* item = new (std::nothrow) WsWorkItem{};
										bool handedOff = false;
										if (item)
										{
											item->kind       = WsWork::Upset;
											item->controlLeg = controlLeg;
											item->partId     = partId;
											item->callerId   = callerId;   // same caller for all (only inbound uses it)
											handedOff = enqueueWsWork(item);
										}
										if (!handedOff)
										{
											// Claimed upsetInFlight above but never actually got a worker to clear
											// it (alloc failed, or the queue — depth kWsQueueDepth=16 — was full).
											// Without this release the coalescing dedup wedges the leg: every later
											// repeat just sets upsetPending with nobody left in flight to notice.
											std::lock_guard<std::mutex> lock(_mutex);
											CallSlot* s = slotForLocked(controlLeg);
											if (s)
											{
												s->upsetInFlight.store(false, std::memory_order_release);
												s->upsetPending.store(false, std::memory_order_release);
											}
										}
									}
								}
								else if (evTypeNum == TEL_EV_REMOVE)
								{
									ESP_LOGI(TAG, "Call control event: Participant Remove %s", partId.c_str());
									// #43: stopMediaStreams() has a <=2 s rx-join — off the WS task.
									// placement new(nothrow) returns an initialized pointer; cppcheck misparses it.
									// cppcheck-suppress legacyUninitvar
									auto* item = new (std::nothrow) WsWorkItem{};
									if (item)
									{
										item->kind   = WsWork::Remove;
										item->partId = partId;
										enqueueWsWork(item);
									}
								}
								else if (evTypeNum == TEL_EV_DTMF)
								{
									cJSON* attached = cJSON_GetObjectItem(eventObj, "attached_data");
									if (attached)
									{
										cJSON* dtmfInput = cJSON_GetObjectItem(attached, "dtmf_input");
										if (dtmfInput && dtmfInput->valuestring && evCb)
										{
											CallEvent ev{CallEvent::Dtmf, partId, dtmfInput->valuestring, ""};
											evCb(ev);
										}
									}
								}
							}
						}
					}
				}
			}
			break;

		default:
			break;
	}
}

bool TelephonyAnchorClient::startRxIfNeeded(const std::string& participantId)
{
	std::lock_guard<std::mutex> lock(_mutex);
	// Find-or-claim THIS participant's call slot (#100). A full table means we are already
	// bridging POCKETDIAL_MAX_ANCHOR_CALLS calls — refuse the new one rather than overrun.
	CallSlot* slot = allocSlotLocked(participantId);
	if (!slot)
	{
		ESP_LOGW(TAG, "startRxIfNeeded: no free call slot for %s (%d concurrent max)",
		         participantId.c_str(), POCKETDIAL_MAX_ANCHOR_CALLS);
		return false;
	}
	if (slot->rxTaskHandle != nullptr)
	{
		// Already polling (ring-time prime or a duplicate call) — nothing to do.
		return true;
	}
	if (slot->rxDoneSem)
	{
		vSemaphoreDelete(slot->rxDoneSem);
	}
	slot->rxDoneSem = xSemaphoreCreateBinary();
	// Heap arg so the static trampoline knows its slot (one-time per call setup, off the hot
	// path — same discipline as the heap WsWorkItem). Freed by the rx task on exit.
	RxTaskArg* arg = new (std::nothrow) RxTaskArg{this, slot};
	if (!arg)
	{
		if (slot->rxDoneSem) { vSemaphoreDelete(slot->rxDoneSem); slot->rxDoneSem = nullptr; }
		return false;
	}
	// #100: stack in PSRAM (WithCaps) — N concurrent calls' GET-rx tasks would otherwise exhaust
	// internal RAM. The task does HTTPS GET reads + the audio rx callback only (no flash writes),
	// so a PSRAM stack is safe. Force-kill + self-exit both use vTaskDeleteWithCaps.
	BaseType_t rc = xTaskCreatePinnedToCoreWithCaps(&TelephonyAnchorClient::rxTaskTrampoline, "tel_media_rx", 6144, arg, 6, &slot->rxTaskHandle, 1, PD_TASK_STACK_CAPS);
	if (rc != pdPASS)
	{
		ESP_LOGE(TAG, "Failed to create Rx task for %s", participantId.c_str());
		delete arg;
		slot->rxTaskHandle = nullptr;
		if (slot->rxDoneSem) { vSemaphoreDelete(slot->rxDoneSem); slot->rxDoneSem = nullptr; }
		return false;
	}
	ESP_LOGI(TAG, "Rx stream task started for participant %s", participantId.c_str());
	return true;
}

bool TelephonyAnchorClient::startMediaStreams(const std::string& participantId)
{
	ESP_LOGI(TAG, "Starting media streams for participant %s", participantId.c_str());

	// Early-out: this participant's slot already has a LIVE POST stream (re-entrant pre-warm vs
	// answer-time fallback). Snapshot the slot under _mutex, then check under its postMutex —
	// never nested, preserving the original lock discipline. (The Rx task alone is NOT a busy
	// signal — it is primed during ringing by startRxIfNeeded.)
	{
		CallSlot* s = nullptr;
		{
			std::lock_guard<std::mutex> lock(_mutex);
			s = slotForLocked(participantId);
		}
		if (s)
		{
			std::lock_guard<std::mutex> postLock(s->postMutex);
			if (s->postLive.load(std::memory_order_acquire))
			{
				ESP_LOGW(TAG, "startMediaStreams: slot for %s already streaming", participantId.c_str());
				return false;
			}
		}
	}

	// 1. Make sure THIS participant's Rx task + slot are up (allocs the slot if new) so its
	// GET-stream handshake/polling overlaps the POST open below. Fails if all slots are busy.
	if (!startRxIfNeeded(participantId))
	{
		return false;
	}

	std::string baseUrl, sourceDn, token;
	CallSlot* slot = nullptr;
	{
		std::lock_guard<std::mutex> lock(_mutex);
		slot = slotForLocked(participantId);
		baseUrl = _baseUrl;
		sourceDn = _sourceDn;
		token = _accessToken;
	}
	if (!slot)
	{
		return false;   // slot vanished (teardown race)
	}

	// 2. Open this slot's HTTP POST client for outbound audio. On failure the caller invokes
	// stopMediaStreams(participantId), which shuts down and joins this slot's Rx task.
	std::string postUrl = baseUrl + "/callcontrol/" + sourceDn + "/participants/" + participantId + "/stream";
	{
		std::lock_guard<std::mutex> postLock(slot->postMutex);
		// Re-check under the lock: a concurrent caller could have raced past the early-out.
		if (slot->postLive.load(std::memory_order_acquire))
		{
			return false;
		}
		if (slot->postClient == nullptr)
		{
			// First open on this slot (boot/teardown): a cold handshake. The handle is then KEPT
			// WARM across calls on this slot so subsequent opens RESUME its TLS session.
			slot->postClient = makeAuthedClient(postUrl, HTTP_METHOD_POST, 4096, token);
			if (!slot->postClient)
			{
				ESP_LOGE(TAG, "Failed to init POST HTTP client");
				return false;
			}
		}
		else
		{
			// Reuse the warm handle: re-point at THIS call's participant + refresh the bearer.
			esp_http_client_set_url(slot->postClient, postUrl.c_str());
			if (!token.empty())
			{
				std::string authHeader = "Bearer " + token;
				esp_http_client_set_header(slot->postClient, "Authorization", authHeader.c_str());
			}
		}

		esp_http_client_set_header(slot->postClient, "Content-Type", "application/octet-stream");

		// write_len = -1 => chunked transfer-encoding (IDF adds Transfer-Encoding; we frame each
		// write ourselves in writeAudio). Do NOT pass 0 (that sent Content-Length:0 and Telephony
		// closed the stream — the old outbound-audio bug).
		const int64_t openT0 = esp_timer_get_time();
		esp_err_t err = esp_http_client_open(slot->postClient, -1);
		if (err != ESP_OK)
		{
			// A REUSED warm handle can be stale; rebuild fresh + retry ONCE (degrades to a cold
			// handshake rather than a failed call).
			ESP_LOGW(TAG, "POST open failed (%s) — rebuilding handle and retrying", esp_err_to_name(err));
			esp_http_client_cleanup(slot->postClient);
			slot->postClient = makeAuthedClient(postUrl, HTTP_METHOD_POST, 4096, token);
			err = ESP_FAIL;
			if (slot->postClient)
			{
				esp_http_client_set_header(slot->postClient, "Content-Type", "application/octet-stream");
				err = esp_http_client_open(slot->postClient, -1);
			}
			if (!slot->postClient || err != ESP_OK)
			{
				ESP_LOGE(TAG, "Failed to open chunked HTTP POST stream: %s", esp_err_to_name(err));
				if (slot->postClient) { esp_http_client_cleanup(slot->postClient); slot->postClient = nullptr; }
				return false;
			}
		}
		// Classify by open wall-time (full ECDHE >400ms vs resumed). Telemetry stays aggregate
		// across slots (shared handshake counters).
		const int64_t openMs = (esp_timer_get_time() - openT0) / 1000;
		const bool fullHandshake = (openMs > 400);
		(fullHandshake ? _postFullHandshakes : _postResumedHandshakes).fetch_add(1, std::memory_order_relaxed);
		ESP_LOGI(TAG, "POST open %lld ms -> %s handshake", (long long)openMs, fullHandshake ? "FULL" : "resumed");
		slot->postLive.store(true, std::memory_order_release);
	}
	ESP_LOGI(TAG, "POST (device->Telephony) audio stream OPEN: %s", postUrl.c_str());

	return true;
}

void TelephonyAnchorClient::stopMediaStreams(const std::string& participantId)
{
	// Find this call's slot (snapshot under _mutex; the slot array never moves).
	CallSlot* slot = nullptr;
	{
		std::lock_guard<std::mutex> lock(_mutex);
		slot = slotForLocked(participantId);
	}
	if (!slot)
	{
		return;   // already torn down / never existed
	}

	// Per-slot single-entry gate: a concurrent caller (WS-disconnect vs stop()) loses the CAS and
	// returns at once, so only the winner frees this slot's getClient. RAII clears it on exit.
	bool expected = false;
	if (!slot->tearingDown.compare_exchange_strong(expected, true))
	{
		return;
	}
	struct ClearOnExit {
		std::atomic<bool>& f;
		~ClearOnExit() { f.store(false, std::memory_order_release); }
	} clearOnExit{slot->tearingDown};

	TaskHandle_t taskToKill = nullptr;
	SemaphoreHandle_t doneSem = nullptr;
	{
		std::lock_guard<std::mutex> lock(_mutex);
		taskToKill = slot->rxTaskHandle;
		// Capture the semaphore under the SAME lock: startRxIfNeeded deletes+recreates rxDoneSem,
		// so re-reading the member after releasing the lock could race a fresh handle (UAF). Use
		// the local 'doneSem' for the whole teardown below, never slot->rxDoneSem.
		doneSem = slot->rxDoneSem;
		slot->rxTaskHandle = nullptr; // signal the rx task to exit
	}

	if (taskToKill)
	{
		{
			std::lock_guard<std::mutex> lock(slot->getMutex);
			if (slot->getClient)
			{
				int fd = esp_http_client_get_socket(slot->getClient);
				if (fd >= 0)
				{
					shutdown(fd, SHUT_RDWR);
				}
			}
		}

		if (doneSem)
		{
			if (xSemaphoreTake(doneSem, pdMS_TO_TICKS(2000)) != pdTRUE)
			{
				ESP_LOGE(TAG, "Rx task failed to exit in time! Forcing task deletion.");
				vTaskDeleteWithCaps(taskToKill);   // #100: rx task is WithCaps(PSRAM) — reclaim its stack
				// try_lock: if the deleted task was holding getMutex when killed, the mutex is
				// permanently poisoned and a blocking lock_guard would deadlock here.
				if (slot->getMutex.try_lock())
				{
					if (slot->getClient)
					{
						esp_http_client_close(slot->getClient);
						esp_http_client_cleanup(slot->getClient);
						slot->getClient = nullptr;
					}
					slot->getMutex.unlock();
				}
				else
				{
					// Issue #65 (L-1): getClient (and its LWIP socket) is unrecoverable in place.
					// Count it; once too many leak, request a full anchor restart so the next
					// stop()/start() reclaims the whole socket pool (done off-SIP by tick()).
					const int leaked = _leakedGetClients.fetch_add(1, std::memory_order_relaxed) + 1;
					ESP_LOGE(TAG, "getMutex poisoned by killed task — leaking getClient to avoid deadlock (%d leaked)", leaked);
					if (leaked >= kLeakRestartThreshold)
					{
						_restartRequested.store(true, std::memory_order_release);
						ESP_LOGW(TAG, "Leaked GET sockets reached %d — requesting anchor restart to reclaim the pool", leaked);
					}
				}
			}
		}
	}
	else
	{
		// No rx task running — safe to clean up directly.
		std::lock_guard<std::mutex> lock(slot->getMutex);
		if (slot->getClient)
		{
			esp_http_client_close(slot->getClient);
			esp_http_client_cleanup(slot->getClient);
			slot->getClient = nullptr;
		}
	}

	{
		std::lock_guard<std::mutex> lock(slot->postMutex);
		if (slot->postLive.load(std::memory_order_acquire) && slot->postClient)
		{
			// RFC 9112 §7.1 last-chunk so Telephony sees end-of-stream, not an aborted socket.
			esp_http_client_write(slot->postClient, "0\r\n\r\n", 5);
			// Close the REQUEST but KEEP the handle: its TLS session resumes on this slot's next
			// call (no ~1s ECDHE). The handle is freed only on full teardown (closePostClient).
			esp_http_client_close(slot->postClient);
			slot->postLive.store(false, std::memory_order_release);
		}
	}

	// Free the slot back to the pool LAST (after the rx task has exited + given its sem, so no
	// realloc can race the teardown). The warm postClient stays for resumption on the next call.
	{
		std::lock_guard<std::mutex> lock(_mutex);
		freeSlotLocked(*slot);
	}
	ESP_LOGI(TAG, "Media streams stopped for %s", participantId.c_str());
}

void TelephonyAnchorClient::rxTaskTrampoline(void* arg)
{
	auto* a = static_cast<RxTaskArg*>(arg);
	TelephonyAnchorClient* self = a->self;
	CallSlot* slot = a->slot;
	delete a;                  // one-time per-call heap arg (see startRxIfNeeded)
	self->runRxLoop(slot);
	// Give THIS slot's done-sem so stopMediaStreams() can join. stop() holds off any realloc of
	// the slot until it has taken this sem, so slot->rxDoneSem is still the one it waits on.
	if (slot->rxDoneSem)
	{
		xSemaphoreGive(slot->rxDoneSem);
	}
	vTaskDeleteWithCaps(nullptr);   // #100: created WithCaps(PSRAM) — reclaim the PSRAM stack/TCB
}

void TelephonyAnchorClient::runRxLoop(CallSlot* slot)
{
	// #100: operate on THIS call's slot. Alias the old single-call member names to the slot's
	// handles (references), so the rest of this function — including its keep-running checks and
	// the GET-stream open/read — drives the right call's stream without per-line edits. _audioCb,
	// _baseUrl/_sourceDn/_accessToken and _mutex stay shared members (correct).
	esp_http_client_handle_t& _getClient           = slot->getClient;
	std::mutex&               _getMutex            = slot->getMutex;
	TaskHandle_t&             _rxTaskHandle        = slot->rxTaskHandle;
	const std::string&        _activeParticipantId = slot->participantId;

	std::string activePartId;
	std::string baseUrl, sourceDn;
	std::string token;
	{
		std::lock_guard<std::mutex> lock(_mutex);
		activePartId = _activeParticipantId;
		baseUrl = _baseUrl;
		sourceDn = _sourceDn;
		token = _accessToken;
	}

	std::string getUrl = baseUrl + "/callcontrol/" + sourceDn + "/participants/" + activePartId + "/stream";

	// _getClient lifecycle (init/close/cleanup) is serialized with
	// stopMediaStreams() via _getMutex so the unblock-close and our teardown can
	// never double-free the handle. The lock is NEVER held across the blocking
	// open/fetch/read calls — stopMediaStreams() must be able to grab it to close
	// the handle and unblock us.
	auto teardownGetClient = [this, &_getClient, &_getMutex]() {
		std::lock_guard<std::mutex> lock(_getMutex);
		if (_getClient)
		{
			esp_http_client_close(_getClient);
			esp_http_client_cleanup(_getClient);
			_getClient = nullptr;
		}
	};

	// The /stream endpoint returns 404 (participant not found yet) or 424 (failed
	// dependency) until the call leg is actually connected and media is flowing.
	// startMediaStreams() can fire slightly ahead of that, so retry the open
	// rather than giving up — otherwise inbound audio is lost for the whole call.
	//
	// LATENCY: the client handle is created ONCE and re-opened across retries so
	// the TLS session persists — the Telephony reference examples do the same with
	// keep-alive agents. The old loop tore the client down per attempt, paying a
	// full mbedTLS handshake (~0.5-1s on the S3) per 404, which serialized into
	// multi-second answer-to-audio delays. Now only the first attempt (or a
	// server-closed connection) pays a handshake; a retry is ~one RTT.
	// 240 attempts ≈ 2 min at the 500ms backoff cap: the task is now started at
	// RINGING, so the loop must comfortably outlast a long unanswered ring (the
	// old 40-attempt/~20s ceiling would expire mid-ring and the call would
	// connect with no inbound audio). Teardown still exits it immediately via
	// _rxTaskHandle/socket shutdown.
	constexpr int        kMaxAttempts = 240;
	TickType_t           delay        = pdMS_TO_TICKS(50);   // Start fast at 50ms
	bool opened = false;

	{
		std::lock_guard<std::mutex> lock(_getMutex);
		if (_rxTaskHandle != nullptr)
		{
			_getClient = makeAuthedClient(getUrl, HTTP_METHOD_GET, 1024, token);
		}
	}

	if (_getClient)
	{
		for (int attempt = 0; attempt < kMaxAttempts && _rxTaskHandle != nullptr; ++attempt)
		{
			const int64_t openT0 = esp_timer_get_time();
			esp_err_t err = esp_http_client_open(_getClient, 0);
			if (err == ESP_OK)
			{
				esp_http_client_fetch_headers(_getClient);
				int status = esp_http_client_get_status_code(_getClient);
				if (status == 200)
				{
					// #100: surface the GET handshake cost — a warm/pre-warmed handle RESUMES (well
					// under ~400 ms), a cold one pays the S3's ~1s software ECDHE. The metric that
					// proves the concurrent-burst wall is lifted.
					const int64_t openMs = (esp_timer_get_time() - openT0) / 1000;
					ESP_LOGI(TAG, "GET open %lld ms -> %s handshake", (long long)openMs, (openMs > 400) ? "FULL" : "resumed");
					opened = true;
					break;
				}
				ESP_LOGW(TAG, "GET stream not ready (HTTP %d), attempt %d/%d", status, attempt + 1, kMaxAttempts);
				// Drain the error body completely so the persistent connection can
				// carry the next attempt (an unread body poisons handle reuse).
				char drainBuf[256];
				while (esp_http_client_read(_getClient, drainBuf, sizeof(drainBuf)) > 0) {}
			}
			else
			{
				// Connection-level failure: esp_http_client re-establishes the
				// transport on the next open, so still no per-retry teardown needed.
				ESP_LOGW(TAG, "GET stream open failed (%s), attempt %d/%d", esp_err_to_name(err), attempt + 1, kMaxAttempts);
			}

			if (_rxTaskHandle != nullptr)
			{
				vTaskDelay(delay);
				delay = (delay * 2 > pdMS_TO_TICKS(500)) ? pdMS_TO_TICKS(500) : delay * 2;
			}
		}
	}

	if (!opened)
	{
		ESP_LOGW(TAG, "GET (Telephony->device) stream never opened — no inbound audio");
		teardownGetClient();
		return;
	}
	ESP_LOGI(TAG, "GET (Telephony->device) audio stream OPEN: %s", getUrl.c_str());

	alignas(2) char readBuf[514]; // +1 for carry byte, +1 for alignment padding; alignas(2) for safe int16_t reinterpret_cast
	bool hasCarry = false;
	char carryByte = 0;
	int rxReads = 0;
	while (_rxTaskHandle != nullptr)
	{
		int bytesRead = 0;
		if (hasCarry)
		{
			readBuf[0] = carryByte;
			int res = esp_http_client_read(_getClient, readBuf + 1, sizeof(readBuf) - 1);
			if (res <= 0)
			{
				break;
			}
			bytesRead = 1 + res;
			hasCarry = false;
		}
		else
		{
			int res = esp_http_client_read(_getClient, readBuf, sizeof(readBuf) - 1);
			if (res <= 0)
			{
				break;
			}
			bytesRead = res;
		}

		if (bytesRead % 2 != 0)
		{
			carryByte = readBuf[bytesRead - 1];
			hasCarry = true;
			bytesRead -= 1;
		}

		if (bytesRead == 0)
		{
			continue;
		}

		// #100: log only the FIRST inbound chunk (confirms the GET stream is live); the periodic
		// per-100-chunk log × N concurrent calls flooded the UART (serial loss). ESP_LOGD for more.
		if (rxReads == 0)
		{
			ESP_LOGI(TAG, "GET read: first chunk %d bytes <- Telephony (%s)", bytesRead, activePartId.c_str());
		}
		rxReads++;

		// Issue #284: fixed on-stack buffer + string_view, not a std::string
		// copy -- this runs once per inbound audio chunk. SBO-safe in practice
		// today (3CX participant ids are short numerics, same premise
		// MediaBridge::kMohParticipantIdBufSize rests on), but unconditionally
		// so rather than relying on that staying true. Refuse rather than
		// truncate on overflow, same guard MediaBridge::feedMohTick() uses for
		// the identical reason: a truncated id could be mistaken for a
		// different call downstream.
		AudioRxCallback audioCb;
		constexpr size_t kPartIdBufSize = 32;
		char partIdBuf[kPartIdBufSize];
		size_t partIdLen = 0;
		bool partIdOk = true;
		{
			std::lock_guard<std::mutex> lock(_mutex);
			audioCb = _audioCb;
			partIdLen = _activeParticipantId.size();   // #100: alias of slot->participantId — routes rx to this call
			if (partIdLen >= sizeof(partIdBuf))
			{
				partIdOk = false;
			}
			else
			{
				std::memcpy(partIdBuf, _activeParticipantId.data(), partIdLen);
			}
		}

		if (audioCb && partIdOk)
		{
			// Process raw bytes into linear PCM16 samples (each sample is 2 bytes, little-endian)
			size_t sampleCount = bytesRead / sizeof(int16_t);
			const int16_t* pcmSamples = reinterpret_cast<const int16_t*>(readBuf);
			if (sampleCount > 0)
			{
				audioCb(std::string_view(partIdBuf, partIdLen), pcmSamples, sampleCount);
			}
		}
	}

	teardownGetClient();
}

#endif
