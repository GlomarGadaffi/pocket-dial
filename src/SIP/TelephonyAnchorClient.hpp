#ifndef TELEPHONY_ANCHOR_CLIENT_HPP
#define TELEPHONY_ANCHOR_CLIENT_HPP

#include "AnchorClient.hpp"
#include <mutex>
#include <string>
#include <string_view>
#include <atomic>
#include <functional>

#if defined(ESP_PLATFORM) || defined(ESP32)
#include "esp_websocket_client.h"
#include "esp_http_client.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"   // #43: WS event work queue
#include "freertos/semphr.h"  // #43: worker-pool done semaphore (+ existing _rxDoneSem)
#endif

#include "PoolConfig.hpp"     // #100: POCKETDIAL_MAX_ANCHOR_CALLS (per-call slot count)

class TelephonyAnchorClient : public AnchorClient
{
public:
	TelephonyAnchorClient();
	~TelephonyAnchorClient() override;

	bool init(const std::string& baseUrl,
	          const std::string& clientId,
	          const std::string& clientSecret,
	          const std::string& sourceDn) override;

	bool start() override;
	void stop() override;
	bool isConnected() const override;
	bool isStreaming() const;
	bool makeCall(const std::string& destination, std::string* ownLegOut = nullptr) override;
	bool answerCall(const std::string& participantId) override;
	bool dropCall(const std::string& participantId) override;
	void setEventCallback(EventCallback cb) override;
	bool writeAudio(std::string_view participantId, const int16_t* pcmSamples, size_t count) override;
	void registerAudioRxCallback(AudioRxCallback cb) override;
	void tick() override;   // non-blocking; runs the _outboundActive reconcile watchdog (ESP only)
	void setRewarmIntervalSec(uint32_t sec) override;  // #107: idle TLS re-warm cadence (s); 0 = off

	// A real provider: makeCall()/resolveOutboundLeg() hand back a DISTINCT
	// participant id per call (TelephonyAnchorClient.cpp:418, "#100: let the engine
	// bind this call's session now"), which is what the engine's rx-audio fan-out
	// keys on — so unlike the loopback mock this can genuinely be driven
	// concurrently, and the binding limit is the engine's array size rather than
	// anything in here.
	//
	// The practical ceiling is NOT sockets or RAM (both were lifted: PSRAM task
	// stacks, a 48-entry LWIP pool). It is that the ESP32-S3 has no ECC
	// acceleration, so every TLS handshake is roughly a second of CPU and a cold
	// start opens two per call (the GET and POST audio streams). Past about four
	// simultaneous handshakes both cores saturate, the idle tasks starve and the
	// task watchdog trips, while the extra calls finish handshaking too late to
	// bridge anything. drawbridge validated 4 on this same silicon as the point
	// where calls still bridge with no playout glitches and the next one is cleanly
	// refused with 503 rather than attempted and dropped.
	unsigned maxConcurrentCalls() const override { return POCKETDIAL_MAX_ANCHOR_CALLS; }

	// Counts of POST media-stream opens by handshake type (set in startMediaStreams from the
	// open's wall time — a full S3 ECDHE is always >~400ms, a resumed session well under).
	void getTlsHandshakeStats(uint32_t& fullOut, uint32_t& resumedOut) const override
	{
		fullOut    = _postFullHandshakes.load(std::memory_order_relaxed);
		resumedOut = _postResumedHandshakes.load(std::memory_order_relaxed);
	}

private:
	std::string _baseUrl;
	std::string _clientId;
	std::string _clientSecret;
	std::string _sourceDn;

	std::atomic<bool> _running{false};
	std::atomic<bool> _connected{false};
	std::string       _accessToken;
	// #100: count of outbound makeCall()s in flight whose own leg is NOT yet resolved (the window
	// between the makecall POST and resolveOutboundLeg keying the slot). While > 0, the WS
	// classifier treats an UNmatched upset as a probable far-leg of an in-flight outbound call
	// rather than a new inbound — so an early upset can't false-ring the extensions. This is the
	// per-slot successor to the old single pre-POST _outboundActive flag.
	std::atomic<int>  _outboundPending{0};

	// #100: outbound/inbound disambiguation, the answer-once one-shot, the makecall-wedge timestamp
	// and the inbound announce-once id all moved ONTO the per-call CallSlot (see the struct below),
	// since each concurrent call needs its own. The shared globals here are only the aggregate TLS
	// handshake telemetry and the watchdog/re-warm bookkeeping.
	// Lifetime counts of POST media-stream opens by TLS handshake type (full ECDHE vs resumed).
	// Surfaced in /api/status telemetry; cross-platform so the host build links the getter.
	std::atomic<uint32_t> _postFullHandshakes{0};
	std::atomic<uint32_t> _postResumedHandshakes{0};
	// One-shot guard: the watchdog spawns at most one reconcile worker at a time.
	std::atomic<bool> _reconcileInFlight{false};
	// Monotonic (esp_timer) timestamp of the last reconcile spawn. #94: the reconcile GET
	// fails with sock<0 while a call holds the TLS sockets, so without a floor the watchdog
	// re-spawned every 1 Hz tick — busy-looping failed connects and ADDING socket pressure.
	// tick() enforces a minimum interval between spawns. Atomic: read on the SIP task,
	// written by the reconcile worker.
	std::atomic<int64_t> _lastReconcileUs{0};
	// Resolved device_id for the device-specific makecall transport, guarded by _mutex. Empty
	// until lazily resolved; cleared on WS disconnect so a device registration flap re-resolves.
	std::string       _deviceId;

	// ── #107: idle TLS re-warm heartbeat ─────────────────────────────────────────
	// Operator-configurable cadence (SECONDS) at which tick() refreshes the persistent POST
	// media-stream TLS session WHILE IDLE, so even the first call after a long quiet stretch
	// resumes its session instead of paying the S3's ~1s software-ECDHE cold handshake (the
	// old answer-time dead air). 0 = disabled. Default 3600 s (1 h); driven from NVS via
	// setRewarmIntervalSec(). Today this is a single PBX-wide cadence (one active anchor); when
	// multi-carrier/multi-call lands (#100) it becomes per-provider. Atomic: written by the
	// config setter, read on the SIP tick.
	std::atomic<uint32_t> _rewarmIntervalSec{3600};
	// One-shot guard so repeated ticks can't double-spawn the re-warm worker.
	std::atomic<bool>     _rewarmInFlight{false};
	// Monotonic (esp_timer) timestamp of the last re-warm spawn; 0 = unseeded (the first idle
	// tick seeds it so the first re-warm fires one full interval after boot, not immediately).
	std::atomic<int64_t>  _lastRewarmUs{0};

	EventCallback   _eventCb;
	AudioRxCallback _audioCb;

	mutable std::mutex _mutex;
	// #100: the POST/GET handle mutexes are now per-CallSlot (postMutex/getMutex in the struct
	// below) — one media stream per concurrent call. _mutex still guards slot alloc/free + the
	// shared credential/token fields.

	// Token lifetime measured against the monotonic timer (not wall clock, so no
	// SNTP dependency). Derived from the JWT's own exp/iat claims, NOT from the
	// OAuth expires_in field — Telephony reports expires_in:60 but the JWT is valid ~1h,
	// and re-issuing a token invalidates the one the active media streams hold.
	int64_t _tokenObtainedUs = 0;
	int64_t _tokenLifetimeUs = 0;

#if defined(ESP_PLATFORM) || defined(ESP32)
	esp_websocket_client_handle_t _wsClient   = nullptr;
	// ── #100: per-call media slot ────────────────────────────────────────────────
	// The anchor shares ONE control plane (WS + ctrl HTTPS + token) but bridges up to
	// POCKETDIAL_MAX_ANCHOR_CALLS concurrent calls, each with its OWN media streams. Every
	// field here is exactly what the old single-call anchor held, now replicated per call and
	// keyed by the participant id (the leg WE control). participantId=="" means a free slot.
	// Alloc/free + participantId + the outbound flags are guarded by _mutex; the media handles
	// by the slot's own postMutex/getMutex (same discipline as the old single _post/_getMutex).
	// The persistent warm postClient is kept alive across calls on this slot for TLS-session
	// resumption (handle!=null no longer means "streaming"; postLive does).
	struct CallSlot
	{
		std::string              participantId;          // "" = free (guarded by _mutex)
		std::atomic<bool>        outboundActive{false};
		std::atomic<bool>        outboundAnswered{false};
		int64_t                  outboundActiveSetUs = 0; // guarded by _mutex
		std::string              inboundSignaledPartId;   // Incoming fired once (guarded by _mutex)
		std::string              farPartId;               // far-leg participant id — populated at Connected so Remove can match it (guarded by _mutex)
		// Telephony repeats an unresolved Upset every ~750ms. Without these, each repeat spawned its own
		// worker, and kWsWorkers==POCKETDIAL_MAX_ANCHOR_CALLS let up to 4 run truly concurrently —
		// each paying its OWN cold getLegStatus() handshake (a fresh esp_http_client per call, so
		// TLS session resumption never kicks in) for what is the SAME still-pending call. upsetInFlight
		// gates this to one status check at a time per slot; a repeat that lands mid-check sets
		// upsetPending instead of spawning a duplicate, and the in-flight worker rechecks once more
		// before clearing the flag — so a genuine Dialing->Connected transition that arrives mid-check
		// is never silently dropped (only identical-phase repeats are collapsed).
		std::atomic<bool>        upsetInFlight{false};
		std::atomic<bool>        upsetPending{false};
		esp_http_client_handle_t postClient = nullptr;
		std::atomic<bool>        postLive{false};         // guarded by postMutex
		esp_http_client_handle_t getClient  = nullptr;
		TaskHandle_t             rxTaskHandle = nullptr;
		SemaphoreHandle_t        rxDoneSem    = nullptr;
		std::atomic<bool>        tearingDown{false};      // single-entry gate for stopMediaStreams(slot)
		mutable std::mutex       postMutex;               // guards postClient (writeAudio/stop)
		std::mutex               getMutex;                // guards getClient (runRxLoop/stop)
	};
	CallSlot _calls[POCKETDIAL_MAX_ANCHOR_CALLS];
	// Slot lookup/alloc (caller holds _mutex). slotForLocked returns the slot whose
	// participantId matches (nullptr if none); allocSlotLocked claims a free slot for a new
	// participant (nullptr if all busy). freeSlotLocked clears a slot back to free.
	// string_view (issue #218 follow-up): writeAudio() can now be called from
	// HoldMusic's real-time pacing task with a participant id that lives in a
	// fixed on-stack buffer, not a std::string -- this must stay allocation-
	// free on that path. Every other call site already holds a std::string,
	// which converts for free.
	CallSlot* slotForLocked(std::string_view participantId);
	CallSlot* allocSlotLocked(const std::string& participantId);
	void      freeSlotLocked(CallSlot& slot);
	// Heap arg handed to a slot's rx task so the static trampoline knows its slot.
	struct RxTaskArg { TelephonyAnchorClient* self; CallSlot* slot; };

	// Persistent control-plane HTTPS connection (makecall / participant drop).
	// Kept open across requests so each command is one RTT instead of a fresh
	// mbedTLS handshake — mirrors the keep-alive agents in the Telephony reference
	// examples. Guarded by _ctrlMutex; never touched under _mutex.
	esp_http_client_handle_t      _ctrlClient = nullptr;
	std::mutex                    _ctrlMutex;

	// Persistent GET connection for the read-body status calls (getLegStatus, reconcileParticipantId,
	// getParticipantCaller, resolveDevice's /devices fallback, resolveOutboundLeg's legacy-path
	// GET) — everything that used to go through httpGetBody() on a fresh esp_http_client each time.
	// A fresh client every call meant save_client_session bought NOTHING (destroying the handle
	// throws the cached ticket away with it), so N concurrent callers (e.g. N outbound calls each
	// resolving their own leg's status under a burst) each paid their own full ~800ms-1s software
	// ECDHE, contending for the S3's single crypto-bound core on top of the media streams' own cold
	// opens — hardware-confirmed as the dominant chunk of the dead-air-to-bridge delay under
	// concurrency. Same fix shape as _postClient/_ctrlClient: keep the handle warm (close, not
	// cleanup, between calls) so a reconnect RESUMES instead of re-doing the ECDHE. One handle
	// serializes these reads across concurrent calls, which is a non-issue here — the S3 can't
	// parallelize the crypto anyway, so serializing turns N concurrent cold handshakes into N
	// sequential ~100-150ms resumed ones instead. Guarded by _statusMutex; never touched under _mutex.
	esp_http_client_handle_t      _statusClient = nullptr;
	std::mutex                    _statusMutex;

	// #100: the rx task handle, its done-sem, and the stopMediaStreams() single-entry gate are now
	// per-CallSlot (rxTaskHandle / rxDoneSem / tearingDown in the struct above) — one rx pump per
	// concurrent call, each torn down independently.

	// Issue #65 (L-1): on the rare 2 s join-timeout path stopMediaStreams() force-kills
	// the rx task with vTaskDelete; if that task was holding the slot's getMutex it is permanently
	// poisoned and we deliberately LEAK its getClient (closing it under a poisoned mutex
	// could deadlock/double-free). Each leak burns one of the 16 LWIP sockets, so we
	// count them and, once kLeakRestartThreshold accumulate, request a full anchor
	// stop()/start() cycle to reclaim the socket pool. The restart runs OFF the SIP
	// task (tick() only spawns the worker — it never blocks).
	std::atomic<int>  _leakedGetClients{0};
	std::atomic<bool> _restartRequested{false};
	std::atomic<bool> _restartInFlight{false};
	// How many leaked GET sockets we tolerate before forcing a reclaiming restart. The
	// pool is 16 and the anchor itself needs 3 persistent sockets + SIP/dashboard/SSH,
	// so a handful of leaks is the safe ceiling before sockets start starving.
	static constexpr int kLeakRestartThreshold = 3;
	// One-shot worker that performs the full stop()/start() reclaim cycle off-SIP.
	static void restartTaskTrampoline(void* arg);
	// Issue #336: same _restartRequested mechanism as the leak-count path above,
	// triggered instead by a disconnected/errored WS with an expiring/expired
	// token -- see its own definition for why reconnect-in-place can't fix this.
	void requestRestartIfTokenStale();

	static void wsEventTrampoline(void* handlerArgs, esp_event_base_t base, int32_t eventId, void* eventData);
	void handleWsEvent(int32_t eventId, void* eventData);

	// ── #43: WS event queue + worker pool ────────────────────────────────────────
	// The esp_websocket_client event task MUST stay responsive to keep answering PINGs
	// (a frozen WS task → missed PONGs → server declares the link dead → full reconnect).
	// So handleWsEvent() does only fast JSON-parse + gating, heap-allocs a WsWorkItem and
	// queues a POINTER (a FreeRTOS queue memcpy's its items — a std::string by value would
	// corrupt the heap), then returns. A worker POOL drains the queue and runs the blocking
	// getLegStatus()/startMediaStreams()/stopMediaStreams() off the WS task. kWsWorkers=1
	// today; >1 parallelises concurrent call setups for the multi-call future (issue #100) —
	// pool-ready by construction.
	enum class WsWork : uint8_t { Upset, Remove };
	struct WsWorkItem
	{
		WsWork      kind = WsWork::Upset;
		std::string controlLeg;   // the leg WE control (own outbound leg, or inbound partId)
		std::string partId;       // the participant Telephony surfaced in the event entity path
		std::string callerId;     // inbound From display name (best-effort)
	};
	static constexpr int kWsWorkers    = POCKETDIAL_MAX_ANCHOR_CALLS; // one worker per concurrent call slot
	static constexpr int kWsQueueDepth = 16;
	QueueHandle_t     _wsWorkQueue = nullptr;
	TaskHandle_t      _wsWorkerHandles[kWsWorkers] = {};
	std::atomic<bool> _wsWorkersRun{false};
	// Counting sem each worker gives right before it self-deletes, so stopWsWorkers() can
	// wait for ALL workers to have left xQueueReceive() before it vQueueDelete()s the queue
	// (deleting a queue with a task blocked on it is UB). Created once, reused across restart.
	SemaphoreHandle_t _wsWorkerDoneSem = nullptr;
	bool startWsWorkers();
	void stopWsWorkers();
	// Takes ownership; deletes + returns false on enqueue failure (alloc-null, queue not
	// ready/full). Callers that claimed a slot's upsetInFlight before enqueueing MUST release
	// it on a false return — otherwise a dropped item wedges that leg (the coalescing dedup
	// then swallows every later repeat with nothing left to un-stick it).
	bool enqueueWsWork(WsWorkItem* item);
	static void wsWorkerTrampoline(void* arg);
	void runWsWorker();
	void processWsWork(const WsWorkItem& w);       // the blocking body, off the WS task

	bool fetchToken();
	bool ensureToken();             // refresh iff expiring AND no media streams active
	bool tokenExpiringSoon() const; // true when within the refresh margin of JWT exp
	bool connectWs();
	// getParticipantStatus() removed (chore #75): the specific-id GET 403s for a
	// non-controlled leg (issue #40). Use getLegStatus() (list-based) instead.

	static void rxTaskTrampoline(void* arg);   // arg is a heap RxTaskArg{self, slot}
	void runRxLoop(CallSlot* slot);

	bool startMediaStreams(const std::string& participantId);
	void stopMediaStreams(const std::string& participantId);
	// Tear down EVERY active call slot (shutdown + WS-disconnect). Snapshots the active
	// participant ids under _mutex, then stopMediaStreams() each (can't hold _mutex across them).
	void stopAllMediaStreams();
	// Non-virtual teardown shared by stop() and the destructor so ~TelephonyAnchorClient()
	// never makes a virtual call (cppcheck virtualCallInConstructor; dynamic binding is
	// not used in a destructor anyway).
	void shutdownImpl();
	// Spawn the Rx task (GET-stream retry loop) if it isn't running yet. Called
	// at RINGING so the loop is already polling on a warm TLS connection when
	// the leg connects — inbound audio then opens ~one RTT after answer.
	// Returns true if the task is running (newly spawned or already up).
	bool startRxIfNeeded(const std::string& participantId);

	esp_http_client_handle_t makeAuthedClient(const std::string& url, esp_http_client_method_t method, int txBufSize, const std::string& token = "");
	bool performAuthedRequest(esp_http_client_handle_t client, int* statusCodeOut = nullptr);
	// One-shot POST on the persistent control connection (creates/repairs the
	// handle as needed; retries once on a stale connection). contentType may be
	// nullptr for an empty-body POST.
	bool performCtrl(const std::string& url, const char* contentType, const std::string& body, int* statusCodeOut = nullptr);
	void warmCtrlConnection();   // pre-establish the control TLS session (boot/reconnect)
	void warmStatusConnection(); // pre-establish the status-GET TLS session (boot/reconnect)
	void closeCtrlClient();      // teardown under _ctrlMutex
	void closePostClient();      // free the persistent warm _postClient (full teardown only), under _postMutex
	void closeStatusClient();    // free the persistent warm _statusClient (full teardown only), under _statusMutex
	bool readJsonStringField(esp_http_client_handle_t client, const std::string& field, std::string& out);

	// Live-state GET helpers (reconcile watchdog + drop-fallback + device resolve). Snapshot
	// creds under _mutex then do blocking I/O lock-free.
	bool httpGetBody(const std::string& url, std::string& bodyOut, int* statusOut = nullptr);
	// First participant id currently on our DN (single-leg assumption), or "" if none / on error.
	std::string reconcileParticipantId();
	// POST + capture the response body (for makecall result.id). Fresh client (not the persistent
	// ctrl connection) so the body is readable; creds snapshot under _mutex, blocking I/O lock-free.
	bool httpPostBody(const std::string& url, const char* contentType, const std::string& body, std::string& respBody, int* statusOut = nullptr);
	// The leg WE control for an outbound call: makecall result.id, else a destination digit-suffix
	// match in the live participant list — the id Telephony authorizes us to stream/drop (issue #40).
	std::string resolveOutboundLeg(const std::string& makecallRespBody, const std::string& destination);
	// Status of a specific leg read from the LIST (GET /participants -> find id). Replaces
	// getParticipantStatus(id), which 403s for a leg this DN cannot directly control (issue #40).
	std::string getLegStatus(const std::string& legId);
	// Best-effort caller display (party_caller_id, else party_caller_name) for an inbound leg
	// from the live participant list — the WS event's attached_data is often null on a route
	// point. "" if unavailable. Blocking GET; call off the WS event task.
	std::string getParticipantCaller(const std::string& legId);
	// Device-specific makecall transport.
	std::string pickDeviceId(const std::string& body);   // parse a /devices array → a device_id
	bool resolveDevice();                                 // GET /devices → pickDeviceId → _deviceId
	// One-shot worker spawned by tick() to clear a wedged _outboundActive (see .cpp).
	static void reconcileTaskTrampoline(void* arg);
	// #107: idle TLS re-warm — one-shot worker (spawned by tick() when idle) that reopens the
	// persistent POST handle to perform a resumed handshake and refresh its session ticket.
	static void rewarmTaskTrampoline(void* arg);
	void rewarmPostSession();   // the blocking re-warm body; runs off the SIP task
	// #100: one-shot (spawned after connect) that cold-primes EVERY slot's POST TLS session (via HTTP
	// keep-alive) so a cold-start concurrent burst RESUMES each per-call POST open (~1 RTT) instead
	// of the S3's ~1s software ECDHE. Per-handle keep-alive only (the warm handle's own connection);
	// NOT a separate session-key cache. POST only: the GET stream's fast teardown shuts the socket to
	// unblock its long-poll read, killing keep-alive, so GET can't stay warm without a timeout-based
	// rx teardown (follow-up). Runs off the SIP task (8 cold handshakes, background, at idle).
	static void prewarmTaskTrampoline(void* arg);
	void prewarmAllSlots();
#endif
};

#endif // TELEPHONY_ANCHOR_CLIENT_HPP
