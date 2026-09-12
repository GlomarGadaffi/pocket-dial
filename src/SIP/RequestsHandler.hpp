#ifndef REQUESTS_HANDLER_HPP
#define REQUESTS_HANDLER_HPP

// Seeds the DEFAULT registrar admission mode at boot (Issue #56).
//
// NOTE: this #define is UNCONDITIONAL, so passing -UPOCKETDIAL_OPEN_REGISTRAR on
// the compiler command line does nothing — the header simply re-defines it. That
// also makes the #else branch further down (which would select Mode::Secure)
// unreachable in practice. Do not document this as a build knob; it is not one.
//
// Mode selection is a RUNTIME setting, persisted in NVS as reg_mode and loaded by
// Registrar::loadMode() at construction. Change it from the dashboard
// (POST /api/registrar), or at flash time via the cfgseed record — see
// docs/LEARN_MODE.md and src/Helpers/DeviceConfig.hpp.
#define POCKETDIAL_OPEN_REGISTRAR

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
#include <lwip/sockets.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#elif defined(__linux__)
#include <netinet/in.h>
#elif defined _WIN32 || defined _WIN64
#include <WinSock2.h>
#endif

#include <functional>
#include <unordered_map>
#include <string>
#include <string_view>
#include <mutex>
#include <optional>
#include <vector>
#include <tuple>
#include <cstdint>
#include <atomic>
#include <chrono>
#include <array>
#include "SipMessage.hpp"
#include "SipClient.hpp"
#include "Session.hpp"
#include "CallDetailRecord.hpp"
#include "PcapCapture.hpp"
#include "PbxConfig.hpp"
#include "DialPlan.hpp"
#include "PbxFeatureConfig.hpp"
#include "CdrRing.hpp"
#include "DtmfFeatureCodes.hpp"
#include "CallForker.hpp"
#include "CallPickup.hpp"
#include "PoolConfig.hpp"   // POCKETDIAL_MAX_ANCHOR_CALLS (concurrent anchor media-bridge count)
#include "RtpSender.hpp"
#include "RtpReceiver.hpp"
#include "AnchorClient.hpp"
#include "LoopbackAnchorClient.hpp"
#include "TelephonyProvider.hpp"
#include "MediaBridge.hpp"
#include "PbxEnv.hpp"
#include "TransactionLayer.hpp"
#include "Registrar.hpp"
#include "RegisterBeeper.hpp"
#include "ParkOrbit.hpp"
#include "BlfSubscriptions.hpp"
#include "ConferenceRoom.hpp"

class RequestsHandler : private PbxEnv
{
public:

	using OnHandledEvent = std::function<void(const sockaddr_in&, std::shared_ptr<SipMessage>)>;

	RequestsHandler(std::string serverIp, int serverPort,
		OnHandledEvent onHandledEvent);

	// Forwarders onto the static pool in SipMessagePool.hpp/.cpp (Issue #53 /
	// #101(A) / #101(E)) — kept as public statics here because SipMessageFactory,
	// the handler table, and the test suite all call them as
	// RequestsHandler::getMessageFromPool(...). See sipmsgpool::getMessageFromPool
	// for the full contract (returns NULL under sustained pressure — check it;
	// the caller's job on refusal is to drop, never to synthesize a response out
	// of the same empty pool).
	static std::shared_ptr<SipMessage> getMessageFromPool(std::string_view message, sockaddr_in src);
	static std::shared_ptr<SipMessage> getMessageFromPool(const SipMessage& source);

	// ── Media beachhead static helpers (pure; host-unit-tested) ──────────────────
	// Build the server's own SDP body for the 440 answer (server media: PCMU on the
	// server's RTP port). Pure formatter — exposed so tests can assert its body and
	// the resulting Content-Length correctness (the 777-bug class).
	// `sendrecv` flips the direction attribute: 440 is a one-way tone (sendonly), a
	// conference leg (888) is two-way (sendrecv) — the phone must know to send audio.
	static std::string buildMediaSdp(const std::string& serverIp, int rtpPort,
		bool sendrecv = false);

	// Parse the caller's RTP destination from an INVITE: the SDP c= line IP (falling
	// back to the INVITE source IP) + the m=audio port via getRtpPort(). Returns false
	// if no usable port is found. Pure/host-testable.
	static bool parseCallerRtp(const std::shared_ptr<SipMessage>& invite,
		std::string& outIp, uint16_t& outPort);

	// `rawBytes`, when non-empty, is the exact bytes recvfrom() delivered for this
	// packet (Issue #105) — used verbatim for the inbound /api/pcap capture below
	// instead of re-serializing the parsed message, so whitespace, compact-header
	// forms, and CRLF/LF tolerance the parser normalized survive in the capture.
	// Left empty (the default) by every caller that doesn't have wire bytes to
	// offer — an in-process-built message or a test calling handle() directly —
	// in which case the capture falls back to request->toString(), same as before.
	void handle(std::shared_ptr<SipMessage> request, std::string_view rawBytes = {});
	void tick();

	std::optional<std::shared_ptr<Session>> getSession(std::string_view callID);

	// ── Dashboard query API (thread-safe) ────────────────────────────
	std::vector<std::pair<std::string, std::string>> getActiveClients();
	std::vector<std::tuple<std::string, std::string, std::string, int>> getActiveSessions();
	void forceDisconnect(const std::string& extension);
	uint64_t getPacketsProcessed() const;
	uint64_t getPacketsDropped() const;   // Issue #38: rate-limited/blocked packets
	// SDP bodies refused by the admission gate in handle() (docs/THREAT_MODEL.md
	// T-7): structurally over-limit or carrying RFC 5939 capability negotiation.
	// Counted whether the refusal went out as a 488 (requests) or as a silent
	// drop (responses, ACK).
	uint64_t getSdpRejected() const;
	size_t getClientCount();
	size_t getSessionCount();
	// Legs currently mixed on the meet-me conference (virtual extension 888); 0 while
	// no room has ever been dialled. Reads the live room, not the dashboard snapshot,
	// so it is exact the instant a leg joins or leaves.
	int getConferenceLegs();

	// Call Detail Records (CDR): a thread-safe snapshot of the recent-call ring,
	// newest first. Copied out under _snapshotMutex like the client/session views.
	std::vector<CallDetailRecord> getCallDetailRecords();

	// Issue #33: a classic libpcap file of the last POCKETDIAL_PCAP_RING_SIZE SIP
	// signaling packets (both directions), ready to write straight to a .pcap and
	// open in Wireshark. Takes _mutex (the capture ring is populated from inside
	// handle()/drainOutbox(), both already under it).
	std::string getPcapCapture();

	// Issue #32: the same capture ring, structured for the dashboard's polling
	// live tracer (GET /api/trace) instead of serialized to a .pcap file.
	std::vector<PcapCapture::TraceRecord> getTraceRecords();

	// Issue #35: zero-touch phone provisioning. Looks `mac` up in the adopted-
	// device registry; `authRequired` tells the caller whether this device
	// needs a SIP password on the wire (Secure mode, or an individually
	// Registrar::secure()'d device) — see ProvisioningConfig.hpp for why the
	// server can never supply that password itself.
	struct ProvisioningInfo
	{
		std::string extension;
		// cppcheck flags this as uninitMemberVarNoCtor. False positive:
		// ProvisioningInfo's only construction site (findProvisioningInfo's
		// return) always brace-initialises both fields.
		// cppcheck-suppress uninitMemberVarNoCtor
		bool authRequired;
	};
	std::optional<ProvisioningInfo> findProvisioningInfo(const std::string& mac);

	// Do Not Disturb (DND): set/query a per-extension flag. setDnd is the mutating
	// path behind POST /api/dnd (thread-safe; takes _mutex). getDndExtensions
	// returns the set of extensions currently in DND from the dashboard snapshot
	// (thread-safe; takes _snapshotMutex). Both are safe to call off the SIP thread.
	void setDnd(const std::string& extension, bool on);
	std::vector<std::string> getDndExtensions();

	// Call forwarding (CFU/CFB/CFNA). setForward mutates one trigger ("always",
	// "busy" or "noanswer") for an extension; an empty target clears it (and the
	// whole entry once all three are empty). Both are thread-safe (take _mutex /
	// _snapshotMutex) and NVS-persisted, mirroring setDnd/getDndExtensions. The
	// getter returns {extension, always, busy, noAnswer} tuples for the dashboard.
	void setForward(const std::string& extension, const std::string& trigger, const std::string& target);
	std::vector<std::tuple<std::string, std::string, std::string, std::string>> getForwards();

	// Ring/hunt groups. setRingGroup replaces a group's membership + mode; an empty
	// member list deletes the group. Thread-safe and NVS-persisted. The getter
	// returns {groupExt, "ringall"|"hunt", "m1,m2,..."} for the dashboard.
	void setRingGroup(const std::string& groupExt, const std::string& members, const std::string& mode);
	std::vector<std::tuple<std::string, std::string, std::string>> getRingGroups();

	// Parked calls snapshot for the TUI: {orbit, parkedExt, parker, secondsParked}.
	std::vector<std::tuple<std::string, std::string, std::string, int>> getParkedCalls();

	// Paging zones (980–989). setPageZone replaces a zone's membership; an empty
	// member list deletes the zone. Thread-safe and NVS-persisted. The getter
	// returns {zoneExt, "m1,m2,..."} pairs for the dashboard.
	void setPageZone(const std::string& zoneExt, const std::string& members);
	std::vector<std::pair<std::string, std::string>> getPageZones();

	// ── Dial plan (Issue #69) ─────────────────────────────────────────────────
	// A bounded, ordered pattern → action rule table (see DialPlan.hpp for the
	// pattern grammar and POCKETDIAL_MAX_DIAL_RULES for the cap). setDialRule
	// upserts one rule: a rule whose pattern is already in the table is edited IN
	// PLACE, keeping its evaluation position; a new pattern is appended, and is
	// refused (logged, not applied) once the table is full. An empty `target`
	// deletes the rule with that pattern. `action` is "group" | "page" | "park".
	//
	// The rule is validated here, not at dial time: the pattern and target must be
	// NVS/JSON-safe tokens (DialPlan.hpp's isDialTokenSafe), the target must have
	// the right shape for the action (980–989 for "page", a real orbit for
	// "park"), and reserved virtual extensions are refused as patterns. Invalid
	// input is logged and dropped — same contract as setRingGroup/setPageZone.
	//
	// Thread-safe (takes _mutex / _snapshotMutex) and NVS-persisted, exactly like
	// setRingGroup. The getter returns {pattern, action, target} triples in TABLE
	// ORDER — the order rules are evaluated in — for the dashboard and the API.
	void setDialRule(const std::string& pattern, const std::string& action, const std::string& target);
	std::vector<std::tuple<std::string, std::string, std::string>> getDialRules();

	// ── Admin extension (Task 2B) ─────────────────────────────────────────────────
	// NVS-persisted extension identity for the administrative endpoint
	// (default "1001", NVS namespace "pbxcfg", key "admin_ext") now lives on
	// DtmfFeatureCodes (see _dtmf below); this forwards to _dtmf.adminExt().
	// cppcheck suggests returning `const std::string&` here (returnByReference).
	// Deliberately not applied: DtmfFeatureCodes's _adminExt is mutated by its
	// saveAdminExt()/load() from other call paths with no lock of its own
	// (callers of this getter are not required to hold _mutex — dashboard/HTTP
	// reads go through here off the SIP thread). Returning by value at least
	// keeps the caller's copy independent once this call returns; a reference
	// would additionally dangle/tear if a concurrent save reallocates the
	// string while the caller still holds it.
	// cppcheck-suppress returnByReference
	std::string getAdminExt() const;

	// ── Admin HTTP-open deadline (PLAN_ADMIN_HTTP_ONLY.md Phase 2) ────────────────
	// Epoch-ms deadline until which HttpServer's accept-loop should accept
	// connections on a provisioned device; 0 means no open window. Written only by
	// grantAdminHttpGraceWindow() below — reached from DtmfFeatureCodes's *4887
	// branch (Phase 3), which already holds _mutex, via the _grantAdminWindow
	// callback; read lock-free here so HttpServer's own accept-loop thread never
	// takes _mutex (invariant I2 — it is the only thread that touches the
	// listen socket).
	uint64_t getAdminHttpOpenUntilMs() const
	{
		return _adminHttpOpenUntilMs.load(std::memory_order_acquire);
	}

	// Called by HttpServer's /api/admin/set-pin handler on a successful PIN
	// set/change. Without this, the operator who just used the web UI to
	// provision the device would lose HTTP access on the very next accept-loop
	// tick (up to ~250ms later) — before they can finish onboarding (WiFi,
	// extensions, ...) — since setting the PIN is exactly what flips
	// AdminAuth::isProvisioned() to true and the dark-by-default gate on.
	// Grants the same TTL window a DTMF trigger would; lock-free (atomic store
	// only), safe to call from the HTTP worker thread. Returns the TTL (seconds)
	// it applied so callers that need it for logging don't have to read
	// _adminHttpTtlSec themselves — DtmfFeatureCodes's *4887 handler reaches
	// this through the _grantAdminWindow callback passed to its constructor
	// (see RequestsHandler's _dtmf member) rather than duplicating this
	// arithmetic; HttpServer's existing caller (the set-PIN handler) ignores
	// the return value.
	uint16_t grantAdminHttpGraceWindow()
	{
		uint16_t ttlSec = _adminHttpTtlSec.load();
		uint64_t untilMs = nowEpochMs() + static_cast<uint64_t>(ttlSec) * 1000ULL;
		_adminHttpOpenUntilMs.store(untilMs, std::memory_order_release);
		return ttlSec;
	}

	// Called by HttpServer's authenticated /api/admin/keepalive endpoint. A
	// fixed 1-hour window, deliberately independent of _adminHttpTtlSec (the
	// DTMF trigger's shorter default) — an operator already logged in via a
	// valid session can push the window out further for extended
	// configuration work without needing to re-trigger from a handset.
	void extendAdminHttpWindowOneHour()
	{
		uint64_t untilMs = nowEpochMs() + 3600ULL * 1000ULL;
		_adminHttpOpenUntilMs.store(untilMs, std::memory_order_release);
	}

#if !defined(ESP_PLATFORM) && !defined(ESP32) && !defined(ARDUINO)
	// Test-only: drive the deadline directly without a real DTMF trigger. Not
	// compiled into device firmware.
	void setAdminHttpOpenUntilMsForTest(uint64_t ms)
	{
		_adminHttpOpenUntilMs.store(ms, std::memory_order_release);
	}

	// Test-only: the anchor MediaBridge currently bridging this Call-ID, or nullptr
	// if none is. Lets a test assert the 555 wiring actually attached a bridge
	// (active state, participant id) without racing RtpSender's real background
	// pacer thread the way reading a live PlayoutBuffer would (see
	// ConferenceRoom_test.cpp's file comment on that race). Not compiled into
	// device firmware.
	MediaBridge* anchorBridgeForCallIdForTest(const std::string& callID)
	{
		for (auto& b : _mediaBridges)
		{
			if (b.isForCallId(callID)) return &b;
		}
		return nullptr;
	}
#endif

	// ── Registrar mode (STAGE 2) ──────────────────────────────────────────────────
	// Runtime registrar policy, replacing the compile-time POCKETDIAL_OPEN_REGISTRAR
	// gate. The policy machine itself lives in Registrar (see Registrar.hpp); these
	// aliases + wrappers keep the public API stable for the dashboard/TUI. Setter
	// takes _mutex; getter reads an atomic so the SIP hot path never locks.
	using RegistrarMode = Registrar::Mode;
	void setRegistrarMode(RegistrarMode mode);
	RegistrarMode getRegistrarMode() const;

	// ── Device registry (STAGE 2: Learn-mode adoption) ────────────────────────────
	// Adopted-device lifecycle for the TUI, owned by the Registrar machine. A device
	// is keyed by its 12-hex MAC and remembers the extension it registered as and
	// whether it has been promoted from first-seen (Learned) to digest-enforced
	// (Secured). All accessors are thread-safe (snapshot mutex) and NVS-persisted.
	using DeviceState = Registrar::DeviceState;
	using AdoptedDevice = Registrar::AdoptedDevice;
	// Snapshot of all adopted devices for the dashboard/TUI (thread-safe).
	std::vector<AdoptedDevice> getAdoptedDevices();
	// Promote a device to Secured (MAC-locked + digest-enforced). Accepts either a
	// 12-hex MAC or an extension (resolved to the device currently bound to it).
	// Returns false if no such device is known. Thread-safe + persisted.
	bool secureDevice(const std::string& macOrExt);
	// Forget a device entirely (drops the adoption record; a later REGISTER re-learns
	// it in Learn mode). Accepts a MAC or an extension. Thread-safe + persisted.
	bool forgetDevice(const std::string& macOrExt);

private:
	void initHandlers();

	// SIP request handlers (camelCase to match C++ convention)
	void onRegister(std::shared_ptr<SipMessage> data);
	void onOptions(std::shared_ptr<SipMessage> data);
	void onCancel(std::shared_ptr<SipMessage> data);
	void onReqTerminated(std::shared_ptr<SipMessage> data);
	// Catch-all for a final failure response (>= 300) with no more specific
	// handler. Its job is the one thing RFC 3261 requires of every one of them:
	// make sure a server-originated INVITE transaction gets its ACK, and let the
	// machine that owns the dialog release it.
	void onFinalFailure(std::shared_ptr<SipMessage> data);
	void onInvite(std::shared_ptr<SipMessage> data);
	void onTrying(std::shared_ptr<SipMessage> data);
	void onRinging(std::shared_ptr<SipMessage> data);
	void onBusy(std::shared_ptr<SipMessage> data);
	void onUnavailable(std::shared_ptr<SipMessage> data);
	void onBye(std::shared_ptr<SipMessage> data);
	void onOk(std::shared_ptr<SipMessage> data);
	void onAck(std::shared_ptr<SipMessage> data);
	void onRefer(std::shared_ptr<SipMessage> data);   // blind transfer (RFC 3515)
	void onMessage(std::shared_ptr<SipMessage> data); // inbound MESSAGE (RFC 3428): ack 200 OK
	void onReinvite(std::shared_ptr<SipMessage> data);  // mid-dialog re-INVITE (hold/resume, RFC 3261 §14)
	void onUpdate(std::shared_ptr<SipMessage> data);    // RFC 3311 mid-dialog UPDATE

	// SDP admission failure (T-7). Requests that take a final response get a
	// 488 Not Acceptable Here whose Warning header names the reason; ACK and
	// responses, which take none, are dropped. Either way the body never reaches
	// a decoder or a peer phone. Called from handle() under _mutex.
	void rejectSdp(const std::shared_ptr<SipMessage>& request, SipMessage::SdpVerdict verdict);

	// onSubscribe: thin dispatch-table shim into the BlfSubscriptions machine
	// (see BlfSubscriptions.hpp). Called from handle() — caller holds _mutex.
	void onSubscribe(std::shared_ptr<SipMessage> data);

	// BLF presence (RFC 6665 / RFC 4235) watcher-dialog FSM. Guarded by _mutex.
	BlfSubscriptions _blf{*this};

	// The DTMF SIP INFO handler (Task 2C) — Signal= digit parsing, the
	// per-Call-ID accumulator, and CLASS/admin-menu dispatch — now lives on
	// DtmfFeatureCodes (see _dtmf below); handle() calls _dtmf.onInfo(request)
	// directly, same single-threaded-SIP-path contract as before.

	// Register beep (signaling-only intercom tone): the outbound UAC dialog FSM
	// lives in RegisterBeeper (see RegisterBeeper.hpp). Guarded by _mutex.
	RegisterBeeper _beeper{*this};

	// ── PbxEnv: shared-infrastructure surface for the extracted machines ───────
	// RequestsHandler is the PbxEnv implementation each decomposed state machine
	// (TransactionLayer, ...) talks back through. All three assume the caller
	// holds _mutex, same as the direct members they forward to.
	void enqueue(const sockaddr_in& to, std::shared_ptr<SipMessage> msg) override
	{
		// A null here means messageFromPool() refused (pool + bounded heap
		// fallback both spent, Issue #101(A)). Dropping it centrally keeps the
		// decomposed machines' `enqueue(addr, messageFromPool(...))` one-liners
		// safe without a check at each, and guarantees drainOutbox() — which
		// dereferences every entry — never sees a null.
		if (!msg) return;
		_outbox.emplace_back(to, std::move(msg));
	}
	std::shared_ptr<SipMessage> messageFromPool(std::string raw, sockaddr_in src) override
	{
		return getMessageFromPool(std::move(raw), src);
	}
	void log(std::string msg, bool isError = false) override
	{
		queueLog(std::move(msg), isError);
	}
	const std::string& localIp() const override { return _localIp; }
	int serverPort() const override { return _serverPort; }
	std::shared_ptr<SipClient> findRegistered(std::string_view number) override
	{
		auto c = findClient(number);
		return c.has_value() ? c.value() : nullptr;
	}
	std::shared_ptr<SipClient> allocVirtualPeer(std::string number, const sockaddr_in& addr) override
	{
		return allocateVirtualPeer(std::move(number), addr);
	}
	std::shared_ptr<Session> allocSession(const std::string& callID,
		const std::shared_ptr<SipClient>& src) override
	{
		return allocateSession(callID, src);
	}
	void insertSession(const std::string& callID, const std::shared_ptr<Session>& session) override
	{
		_sessions.emplace(callID, session);
	}
	std::shared_ptr<Session> findSession(std::string_view callID) override
	{
		auto s = getSession(callID);
		return s.has_value() ? s.value() : nullptr;
	}
	std::string contactFor(std::string_view number) const override
	{
		return buildContact(number);
	}
	std::shared_ptr<SipMessage> serverBye(const std::string& destExt,
		const sockaddr_in& destAddr, const std::string& callId,
		const std::string& fromHeader, const std::string& toHeader) override
	{
		return buildServerBye(destExt, destAddr, callId, fromHeader, toHeader);
	}
	void forEachSessionInvolving(std::string_view aor,
		const std::function<void(const std::string&, const Session&, DialogRole)>& fn) const override
	{
		for (const auto& [callID, session] : _sessions)
		{
			if (!session) continue;
			if (session->getSrc() && session->getSrc()->getNumber() == aor)
				fn(callID, *session, DialogRole::Caller);
			if (session->getDest() && session->getDest()->getNumber() == aor)
				fn(callID, *session, DialogRole::Callee);
		}
	}
	bool validAor(std::string_view s) const override
	{
		return isValidAor(s);
	}
	int requestedExpires(const std::shared_ptr<SipMessage>& msg) const override
	{
		return parseRequestedExpires(msg);
	}

	// RFC 3261 §17 INVITE client transactions (Timer A/B/L). Guarded by _mutex.
	TransactionLayer _txLayer{*this};

	// REGISTER admission policy + adopted-device registry (STAGE 2). Guarded by
	// _mutex except the lock-free mode atomic. The compile-time
	// POCKETDIAL_OPEN_REGISTRAR symbol only seeds the DEFAULT mode at boot; the
	// NVS-persisted value (loaded in the constructor) overrides it.
#ifdef POCKETDIAL_OPEN_REGISTRAR
	Registrar _registrar{*this, Registrar::Mode::Open};
#else
	Registrar _registrar{*this, Registrar::Mode::Secure};
#endif

	// RFC 4028 session timer helpers. Caller holds _mutex.
	void armSessionTimer(Session* session, const std::shared_ptr<SipMessage>& ok200);
	void sweepSessionTimers(std::chrono::steady_clock::time_point now);

	// Call parking / park-orbit: the orbit FSM lives in ParkOrbit (see
	// ParkOrbit.hpp). Guarded by _mutex.
	ParkOrbit _park{*this};

	// Mirror the park orbits into the dashboard snapshot. Caller holds _mutex;
	// takes _snapshotMutex internally.
	void refreshParkSnapshot();

	bool setCallState(std::string_view callID, Session::State state);
	void endCall(std::string_view callID, std::string_view srcNumber, std::string_view destNumber, std::string_view reason = "");

	// CDR ring buffer moved to CdrRing.hpp (see _cdr below); endCall() now calls
	// _cdr.record(...) directly, same "caller holds _mutex" contract as before.
	uint64_t nowEpochMs() const;

	// DND/forward/ring-group/page-zone/dial-plan lookups and the Locked mutation
	// cores that used to live here directly now live on the _cfg member (see
	// PbxFeatureConfig.hpp) — callers throughout this file (onInvite(), onBusy(),
	// tick()) and DtmfFeatureCodes::onInfo() (see _dtmf below) reach them as
	// _cfg.xxx(...), all while already holding _mutex, exactly as before.

	// ── Dial-plan dispatch (Issue #69) + fork/group routing ──────────────────────
	// routePageZone/routeRingGroup/routeDialPlan, plus the shared fork/hunt/
	// redirect/cancel core they and onInvite()/onBusy()/onUnavailable()/onRefer()/
	// tick() all call, now live on _forker (CallForker.hpp) — reached as
	// _forker.xxx(...), all while already holding _mutex, exactly as before.

	// ── Directed / group call pickup (Issue #68) ──────────────────────────────
	// See PbxConfig.hpp's isGroupPickupCode/directedPickupTarget doc comment for
	// why pickup groups reuse ring-group membership rather than adding a new
	// config table. All four assume the caller holds _mutex (called from
	// onInvite()/onOk()/onBye(), which already do).

	// pickupPeersOf(ext) — every OTHER extension co-membered with `ext` in any
	// configured ring group — now lives on _cfg (PbxFeatureConfig), a pure
	// membership query over ring-group config; called here as
	// _cfg.pickupPeersOf(...).

	// True iff `session` is currently ringing `ext` (state == Invited AND
	// either it's `ext`'s stored direct-call invite, or `ext` is one of its
	// broadcast/ring-all/hunt pendingTargets).
	bool isSessionRingingExt(const std::shared_ptr<Session>& session, const std::string& ext) const;

	// Scans _sessions for the OLDEST Invited session ringing any of
	// `candidates` (directed pickup passes a single-element vector; group
	// pickup passes the picker's full peer list). On a match, fills
	// `outCallId`/`outExt` with the winning session's Call-ID and which
	// candidate it was ringing. Returns nullptr if none match.
	std::shared_ptr<Session> findRingingSessionAmong(const std::vector<std::string>& candidates,
		std::string& outCallId, std::string& outExt) const;

	// Everything AFTER finding the ringing session — the 486 rejection, the two
	// 200 OKs that bridge the caller's and picker's independent dialogs via
	// Session::peerCallID (see onBye's peerCallID branch for teardown), and
	// cancelling every other still-ringing fork — now lives on _pickup
	// (CallPickup.hpp) as complete(data, picker, ringing, ringingCallId,
	// ringingExt). findRingingSessionAmong's raw _sessions scan above STAYS
	// here (highest session coupling — same reasoning as keeping the 999
	// target-selection loop in onInvite rather than growing PbxEnv with a
	// mutable all-sessions visitor); onInvite's two pickup branches call
	// findRingingSessionAmong themselves, then _pickup.complete(...) with the
	// result.

	// Build a NOTIFY (Event: refer) carrying a message/sipfrag body reporting the
	// transfer result back to the transferor. Caller holds _mutex.
	std::shared_ptr<SipMessage> buildReferNotify(const std::shared_ptr<SipMessage>& refer,
		const std::shared_ptr<SipClient>& transferor,
		const std::string& sipfrag,
		bool terminated);

	// Attended transfer (RFC 3891 Replaces), issue #131: onRefer() splices two live
	// P2P sessions (A-B and A-C) into one B-C call via cross re-INVITEs carrying
	// swapped SDP, then drops A. handleTransferOk() (called from onOk() before the
	// normal session lookup, same pattern as _beeper.handleOk()/_park.handleOk())
	// intercepts the 200 OK to each splice re-INVITE (CSeq 100, tracked by Call-ID
	// in _transferPendingAcks) and ACKs it directly — it must never reach the
	// generic relay below, which would forward it toward A, who is already gone.
	// Caller holds _mutex.
	bool handleTransferOk(const std::shared_ptr<SipMessage>& data);

	// ── Media beachhead: virtual extension 440 (server-sourced RTP tone) ─────────
	// onInvite() routes a dial of 440 here. The server answers 200 OK advertising its
	// OWN media (server IP:port, m=audio <svrport> RTP/AVP 0, PCMU) and starts the
	// one-way RTP tone stream to the caller's RTP address. ONE concurrent stream: a
	// 2nd dial while busy is rejected 486 Busy Here. Caller holds _mutex.
	void onMediaInvite(std::shared_ptr<SipMessage> data, const std::shared_ptr<SipClient>& caller);

	// ── Local N-way conference: virtual extension 888 (server-mixed RTP) ─────────
	// onInvite() routes a dial of 888 here (Issue #75). The server answers 200 OK
	// advertising THIS LEG's own RTP receive port and joins the caller to the shared
	// ConferenceRoom, whose single MixBus gives every leg the sum of the others minus
	// itself. The room is created on the first dial-in and then kept alive (its bus
	// rings and mix-tick task are not worth churning per call). A dial past
	// POCKETDIAL_CONF_LEGS is rejected 486 Busy Here, mirroring the 440 cap. Caller
	// holds _mutex.
	void onConferenceInvite(std::shared_ptr<SipMessage> data, const std::shared_ptr<SipClient>& caller);

	// The shared meet-me room, created lazily on the first 888 dial-in — a MixBus and
	// its per-leg rings are ~50 KB, too much to pay at boot on a node that may never
	// hold a conference. Null until then. Caller holds _mutex.
	std::unique_ptr<ConferenceRoom> _conference;

	// ── Anchored media: virtual extension 555 (bridge to an AnchorClient) ────────
	// onInvite() routes a dial of 555 here — the docs/FEATURE_ROADMAP.md "Anchored
	// media (opt-in, unwired)" extension point, now wired into call routing.
	// AnchorClient/MediaBridge/TelephonyProvider are all vendor-neutral; pocket-dial
	// ships only LoopbackAnchorClient as the concrete provider (see
	// TelephonyProvider.hpp's class comment). Chosen as a dedicated reserved virtual
	// extension — matching the established 777/440/888/999 style — rather than a
	// trunk-access prefix or an unregistered-number fallback: there is no dialed
	// destination digit string to carry (see onAnchorInvite()'s comment on the
	// makeCall() `destination` argument), so a fixed feature code is the natural
	// fit, and unlike a bare "unregistered falls through to the anchor" rule it can
	// never collide with — or silently start bridging — a mistyped real extension.
	// Caller holds _mutex.
	void onAnchorInvite(std::shared_ptr<SipMessage> data, const std::shared_ptr<SipClient>& caller);

	// First anchor media bridge with no active call, or nullptr if every slot is
	// busy (onAnchorInvite() then answers 503 Service Unavailable, mirroring the
	// 440/888 busy-refusal shape with a different status for the different meaning
	// — see that call site's comment). Caller holds _mutex.
	MediaBridge* acquireFreeAnchorBridge();

	void unregisterClient(std::string_view number);

	// Registration-lease handling (RFC 3261 §10.2.1)
	int parseRequestedExpires(const std::shared_ptr<SipMessage>& data) const;
	void sweepExpired();   // evict expired bindings; caller must hold _mutex
	void maybeSweep();     // throttled sweep; caller must hold _mutex

	std::optional<std::shared_ptr<SipClient>> findClient(std::string_view number);
	std::optional<std::shared_ptr<SipClient>> findClientByAddress(const sockaddr_in& addr);
	std::shared_ptr<SipMessage> buildOptionsPing(const std::shared_ptr<SipClient>& client);

	// ── Outbound SIP MESSAGE (STAGE 2) ────────────────────────────────────────────
	// Originate a one-shot SIP MESSAGE (RFC 3428, Content-Type text/plain) to a
	// registered extension — e.g. to notify a phone/operator of a freshly assigned
	// secret. Mirrors the register-beep UAC enqueue (build + _outbox), best-effort:
	// returns false (no enqueue) if `ext` is not currently registered. The body is
	// length-bounded to keep the message in a single UDP datagram. Thread-safe: takes
	// _mutex. Safe to call off the SIP thread (the TUI/admin path).
	bool sendMessageTo(const std::string& ext, const std::string& text);

	// Broadcast / all-page extension (Issue #37). startPaging/handlePagingAnswer/
	// buildPagingBye below are declared but were already never defined or called
	// anywhere in the codebase before this step (paging routes through
	// startBroadcastFork instead, now on _forker) — left as-is; removing unused
	// declarations is a separate cleanup, not this step's job. buildCancel moved
	// to _forker.buildCancel(...) (CallForker.hpp) — it IS called, from tick()
	// and CallPickup::complete().
	void startPaging(std::shared_ptr<SipMessage> invite, std::shared_ptr<SipClient> caller);
	void handlePagingAnswer(const std::shared_ptr<Session>& session, std::shared_ptr<SipMessage> data);
	std::shared_ptr<SipMessage> buildPagingBye(const std::shared_ptr<SipMessage>& ok,
		const std::shared_ptr<SipClient>& answerer);

	// Issue #38: per-source-IP token bucket + optional allowlist. Both helpers
	// assume the caller already holds _mutex.
	bool ipAllowed(const sockaddr_in& src) const;
	bool allowPacket(const sockaddr_in& src);

	void endHandle(std::string_view destNumber, std::shared_ptr<SipMessage> message);
	std::string buildContact(std::string_view number) const;

	bool isValidAor(std::string_view s) const;
	void queueLog(std::string msg, bool isError = false);

	std::shared_ptr<SipClient> allocateClient(std::string number, sockaddr_in address, int expiresSeconds);
	std::shared_ptr<Session> allocateSession(std::string callID, std::shared_ptr<SipClient> src);
	// Draw a transient virtual-peer SipClient (777/440/park leg) from the fixed pool
	// instead of make_shared'ing one in the packet handler. Falls back to heap on
	// exhaustion (graceful, never a crash). Caller holds _mutex.
	std::shared_ptr<SipClient> allocateVirtualPeer(std::string number, sockaddr_in address, int expiresSeconds = 3600);

	// Build a 200 OK with an SDP body for an INVITE (used by 777, park, onReinvite).
	std::shared_ptr<SipMessage> buildOkWithSdp(const std::shared_ptr<SipMessage>& inviteMsg,
		const std::string& activeIp, const std::string& toTag, const std::string& sdpBody);
	// Build a server-initiated in-dialog BYE. From/To must include tags because the
	// dialog role differs per call path (beep = server UAC; park = server UAS).
	std::shared_ptr<SipMessage> buildServerBye(const std::string& destExt,
		const sockaddr_in& destAddr, const std::string& callId,
		const std::string& fromHeader, const std::string& toHeader);

	// Verify that the in-dialog request comes from a peer recorded at dialog setup
	// (source IP match). Returns false → respond 403 Forbidden. Caller holds _mutex.
	bool isDialogSourceAuthorized(const std::shared_ptr<Session>& session,
		const sockaddr_in& source) const;

	// Server-side RTP media source (the 440 tone stream). One concurrent stream; the
	// ESP-only UDP socket + 20 ms pacing task live inside it, guarded for host builds.
	RtpSender _rtpSender;

	// ── Anchored media (555): the AnchorClient/MediaBridge wiring ────────────────
	// POCKETDIAL_MAX_ANCHOR_CALLS concurrent bridges, each owning its own RTP
	// receiver/sender pair (parallel arrays, index-matched) — mirrors _conference's
	// per-leg RTP tasks. _loopbackClient is the only AnchorClient implementation
	// this project ships; _anchorClient points at whatever the boot-time provider
	// registry selected (see the constructor) so every call site below goes through
	// one pointer instead of the concrete type, the same indirection
	// TelephonyProviderRegistry exists to provide.
	//
	// Declaration order matters here: _mediaBridges MUST come after
	// _anchorRtpReceivers/_anchorRtpSenders/_loopbackClient/_anchorClient so it is
	// destroyed FIRST (C++ destroys members in REVERSE declaration order) —
	// ~MediaBridge() calls stopBridge(), which dereferences _receiver/_sender/
	// _anchor, and those must still be alive when that runs.
	RtpReceiver _anchorRtpReceivers[POCKETDIAL_MAX_ANCHOR_CALLS];
	RtpSender   _anchorRtpSenders[POCKETDIAL_MAX_ANCHOR_CALLS];
	LoopbackAnchorClient _loopbackClient;
	TelephonyProviderRegistry _providerRegistry;
	AnchorClient* _anchorClient = nullptr;
	MediaBridge _mediaBridges[POCKETDIAL_MAX_ANCHOR_CALLS];

	// RequestsHandler.hpp: Issues #24 and #28 resolved.
	std::unordered_map<std::string, std::function<void(std::shared_ptr<SipMessage> request)>> _handlers;
	std::unordered_map<std::string, std::shared_ptr<Session>>   _sessions;

	// Call-IDs of attended-transfer splice re-INVITEs (issue #131) pending their
	// 200 OK -> ACK, so handleTransferOk() can find them (same bounded-vector
	// pattern as ParkOrbit's own _pendingAcks). At most two entries live per
	// transfer (the B leg and the C leg); endCall() erases any entry for the
	// Call-ID it tears down, so a leg that dies mid-splice can't leak one forever.
	std::vector<std::string> _transferPendingAcks;

	std::mutex _mutex;
	OnHandledEvent _onHandled;
	std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>> _outbox;
	// Take everything queued this pass, registering outgoing INVITEs for
	// retransmit on the way out. The one place messages leave _outbox — see the
	// #70 ordering note on the definition. Caller holds _mutex.
	std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>> drainOutbox();

	std::string _serverIp;
	std::string _localIp;   // resolved once at construction; avoids getPrimaryLocalIP() under _mutex
	int         _serverPort;

	std::atomic<uint64_t> _packetsProcessed{0};
	std::atomic<uint64_t> _packetsDropped{0};
	std::atomic<uint64_t> _sdpRejected{0};    // T-7 SDP admission refusals

	struct RegistrarSnapshot
	{
		std::vector<std::pair<std::string, std::string>> clients;
		std::vector<std::tuple<std::string, std::string, std::string, int>> sessions;
		std::vector<CallDetailRecord> cdr;   // newest first
		std::vector<std::string> dnd;        // extensions currently in DND
		// Call-forward config: {extension, always, busy, noAnswer}.
		std::vector<std::tuple<std::string, std::string, std::string, std::string>> forwards;
		// Ring/hunt groups: {groupExt, "ringall"|"hunt", "m1,m2,..."}.
		std::vector<std::tuple<std::string, std::string, std::string>> ringGroups;
		// Parked calls: {orbit, parkedExt, parker, secondsParked}.
		std::vector<std::tuple<std::string, std::string, std::string, int>> parkedCalls;
		// Paging zones: {zoneExt, "m1,m2,..."}.
		std::vector<std::pair<std::string, std::string>> pageZones;
		// Dial-plan rules (Issue #69): {pattern, "group"|"page"|"park", target},
		// in table order — the order they are evaluated in. Unlike pageZones this
		// is rebuilt from _cfg's dial plan every tick() alongside ringGroups, so
		// it needs no out-of-band carry-over across the snapshot swap.
		std::vector<std::tuple<std::string, std::string, std::string>> dialRules;
		// Adopted devices (STAGE 2): {mac, ext, state, online}. Mirrored from the
		// Registrar's registry under _mutex; copied out under _snapshotMutex.
		std::vector<AdoptedDevice> devices;
		uint64_t packetsProcessed = 0;
		uint64_t packetsDropped = 0;
	};
	RegistrarSnapshot _snapshot;
	std::mutex _snapshotMutex;

	// CDR ring buffer (Phase 2) now lives on CdrRing.hpp — data, NVS persistence,
	// snapshot copy, and the *69 last-caller lookup, all still guarded by this
	// engine's _mutex. See CdrRing.hpp's class comment for why it takes no
	// PbxEnv reference (unlike _cfg above, nothing about a CDR write needs to
	// refresh the dashboard snapshot immediately).
	CdrRing _cdr;

	// Issue #33: /api/pcap ring. Populated from handle() (inbound) and
	// drainOutbox() (outbound), both already under _mutex.
	PcapCapture _pcapCapture;

	// The five DND/forward/ring-group/page-zone/dial-plan tables live on _cfg now
	// (PbxFeatureConfig.hpp) — data + validation + NVS persistence, all still
	// guarded by this engine's _mutex (see PbxFeatureConfig's class comment for
	// why it takes a callback instead of touching _snapshot/_snapshotMutex
	// directly).
	PbxFeatureConfig _cfg{*this,
		[this](PbxFeatureConfig::Table t) { refreshPbxConfigSnapshot(t); }};
	// Mirrors one of _cfg's five tables into the dashboard snapshot immediately
	// after a mutation (Issue #77) — the callback _cfg invokes on every DND/
	// forward/ring-group/page-zone/dial-rule change, whether it came from the
	// public HTTP-facing setters or from DtmfFeatureCodes::onInfo()'s CLASS
	// codes (already inside _mutex via handle()). Caller holds _mutex; takes
	// _snapshotMutex internally, same nesting as every other snapshot refresh
	// in this class.
	void refreshPbxConfigSnapshot(PbxFeatureConfig::Table t);

	// How long to wait between OPTIONS keepalive cycles, in minutes. Atomic so the
	// TUI can read without taking _mutex. Persisted to NVS ("pbxcfg"/"rewarm_min").
	std::atomic<uint16_t> _rewarmMinutes{60};

	// ── Admin HTTP-open TTL (PLAN_ADMIN_HTTP_ONLY.md Phase 2) ─────────────────────
	// How long a DTMF trigger keeps the HTTP admin plane reachable, in seconds.
	// Atomic (mirrors _registrarMode) so HttpServer's accept-loop can read it
	// lock-free. Read-only from firmware: loadAdminHttpTtl() honors a value
	// provisioned out-of-band in NVS (namespace "pbxcfg", key "admin_http_ttl"),
	// but no code path changes it at runtime, so there is no write-through.
	std::atomic<uint64_t> _adminHttpOpenUntilMs{0};
	std::atomic<uint16_t> _adminHttpTtlSec{600};
	void loadAdminHttpTtl();              // boot-time reload from NVS; caller holds _mutex

	// Mirror the Registrar's adopted-device registry into the dashboard snapshot.
	// Caller holds _mutex; takes _snapshotMutex internally.
	void refreshDeviceSnapshot();
	// Mirror a Registrar registry change into the dashboard snapshot, taking the
	// cheap in-place path for an online-flag-only change. Caller holds _mutex.
	void applyDeviceChange(Registrar::Change change);

	// _cfg.loadPbxConfig() (boot-time reload) and the four persist* write-throughs
	// now live on PbxFeatureConfig; NVS persistence for _forwards / _ringGroups /
	// _pageZones / _dialPlan is unchanged, just relocated.

	// _cdr.load() (boot-time reload) and _cdr.record()'s write-through persist
	// now live on CdrRing; the "cdrlog" NVS namespace and record shape are
	// unchanged, just relocated.

	// Pre-allocated static memory pools (Issue #53). The SipMessage pool itself
	// now lives in SipMessagePool.hpp/.cpp (static there, not a member here).
	std::vector<std::shared_ptr<SipClient>> _clientPool;
	std::vector<std::shared_ptr<Session>> _sessionPool;
	// Virtual-peer pool: transient SipClient slots for 777/440/park legs (Issue #70).
	std::vector<std::shared_ptr<SipClient>> _virtualPeerPool;

	// Issue #38: token bucket keyed by source IPv4 (network-order s_addr).
	struct RateBucket
	{
		// cppcheck flags this as uninitMemberVarNoCtor. False positive: every
		// RateBucket is created via `_rateBuckets[ip] = { 40.0, now }` (below),
		// so `tokens` is overwritten immediately and is never read from the
		// briefly-default-constructed instance operator[] creates first.
		// cppcheck-suppress uninitMemberVarNoCtor
		double tokens;
		std::chrono::steady_clock::time_point last;
	};
	std::unordered_map<uint32_t, RateBucket> _rateBuckets;
	// Optional CIDR allowlist (host order). _allowMask == 0 means "no allowlist".
	uint32_t _allowNet  = 0;
	uint32_t _allowMask = 0;
	// Dedicated lock for the rate-limit state (_rateBuckets / allowlist), held
	// for the per-packet admission check BEFORE the big handler _mutex so a flood
	// from blocked IPs is dropped without ever serializing on _mutex against
	// legitimate signaling. Lock order: never acquire _mutex while holding this;
	// tick() may nest this inside _mutex (the only place both are held), so the
	// one ordering is _mutex → _rateMutex and handle() holds them disjointly.
	std::mutex _rateMutex;

	std::chrono::steady_clock::time_point _lastSweep{};
	std::chrono::steady_clock::time_point _lastTick{};

	std::vector<std::pair<bool, std::string>> _logQueue;

	// The admin extension identity (Task 2B: _adminExt, loadAdminExt/
	// saveAdminExt) and the DTMF digit-collection state machine + CLASS/admin
	// dispatch (Task 2C: DtmfAccum, _dtmfState, onDtmfInfo) now live on
	// DtmfFeatureCodes. It takes _cfg (the *60/*80/*73/*72 CLASS codes) and
	// _cdr (the *69 last-caller lookup) by reference, and reaches
	// grantAdminHttpGraceWindow() through a callback rather than duplicating
	// its epoch-ms-plus-TTL arithmetic (see that method's comment above).
	// Guarded by this engine's _mutex, same "single-threaded SIP handler path"
	// contract the original onDtmfInfo() documented.
	DtmfFeatureCodes _dtmf{*this, _cfg, _cdr,
		[this]() { return grantAdminHttpGraceWindow(); }};

	// The fork/group/dial-plan routing engine (buildInviteFork, startBroadcastFork,
	// huntRingNext, redirectInvite, buildCancel, routePageZone, routeRingGroup,
	// routeDialPlan) now lives on CallForker. It takes _cfg (dial-plan/ring-group/
	// page-zone lookups) and _park (the ParkOrbit dial-plan action reaches
	// _park.orbitIndex()/_park.onInvite() directly, a sibling reference like _cfg,
	// not a new PbxEnv virtual) by reference. Declared after both. Guarded by this
	// engine's _mutex, same convention as every other extracted machine.
	CallForker _forker{*this, _cfg, _park};

	// Directed/group call pickup completion (Issue #68) — see the comment above
	// findRingingSessionAmong for why the session-table scan stays here while
	// only the completion logic moves to _pickup. Declared after _forker (it
	// holds a CallForker& for buildCancel). Guarded by this engine's _mutex.
	CallPickup _pickup{*this, _forker};
};

#endif
