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
#include <iostream>
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
#include <thread>   // host-build async anchor-start worker (_anchorStartThread below)
#include "SipMessage.hpp"
#include "SipClient.hpp"
#include "Session.hpp"
#include "CallDetailRecord.hpp"
#include "PcapCapture.hpp"
#include "PbxConfig.hpp"
#include "DialPlan.hpp"
#include "EmergencyCall.hpp"  // Issue #166: pbx::EmergencyDial
#include "PbxFeatureConfig.hpp"
#include "CdrRing.hpp"
#include "DtmfFeatureCodes.hpp"
#include "CallForker.hpp"
#include "CallPickup.hpp"
#include "PoolConfig.hpp"   // POCKETDIAL_MAX_ANCHOR_CALLS (concurrent anchor media-bridge count)
#include "ServiceExtensions.hpp"   // Issue #202: the engine-owned pseudo-AOR table
#include "RtpSender.hpp"
#include "RtpReceiver.hpp"
#include "SipTrunk.hpp"
#include "TrunkResolver.hpp"
#include "AnchorClient.hpp"
#include "LoopbackAnchorClient.hpp"
#include "TelephonyAnchorClient.hpp"
#include "TelephonyProvider.hpp"
#include "TelephonyApiConfig.hpp"
#include "DidMapping.hpp"
#include "MediaBridge.hpp"
#include "VoicemailLeg.hpp"
#include "VoicemailArchive.hpp"
#include "VoicemailMenu.hpp"
#include "PbxEnv.hpp"
#include "TransactionLayer.hpp"
#include "Registrar.hpp"
#include "RegisterBeeper.hpp"
#include "ParkOrbit.hpp"
#include "BlfSubscriptions.hpp"
#include "ConferenceRoom.hpp"

// SipTrunk::Listener is a PRIVATE base for the same reason PbxEnv is: these
// are inward-facing contracts the engine implements for its own machines, not
// part of the surface a caller gets. setListener(this) happens in the
// constructor, where the conversion to Listener* is accessible.
class RequestsHandler : private PbxEnv, private SipTrunk::Listener
{
public:

	using OnHandledEvent = std::function<void(const sockaddr_in&, std::shared_ptr<SipMessage>)>;

	RequestsHandler(std::string serverIp, int serverPort,
		OnHandledEvent onHandledEvent);
	// Stage A of the TelephonyAnchorClient port (drawbridge): joins the host-build
	// async anchor-start thread (see _anchorStartThread below) and stops the
	// selected anchor client BEFORE member destruction begins — the loopback
	// client's simulation threads call back into this handler, and a real
	// anchor's WS/media worker tasks touch _mutex/_sessions too, so both must be
	// torn down while those members are still alive (mirrors drawbridge's
	// ~RequestsHandler exactly).
	~RequestsHandler();

	// Non-copyable: already implicitly true (a std::mutex member alone
	// deletes the implicit copy ctor/operator=), but this engine class also
	// owns live sockets/RTP tasks/PSRAM buffers directly -- copying it
	// would silently duplicate the mutex-protected state, not the
	// resources it guards. Declared explicitly (found via CI cppcheck
	// 2.21.0's noCopyConstructor/noOperatorEq, tripped once the voicemail
	// slice added more directly-owned dynamic-resource members) so the
	// invariant is documented rather than only accidentally true.
	RequestsHandler(const RequestsHandler&) = delete;
	RequestsHandler& operator=(const RequestsHandler&) = delete;

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
	// `dtmfPt` echoes the caller's RFC 4733 telephone-event payload type (from
	// SipMessage::getTelephoneEventPayloadType()) so DTMF can reach a
	// server-terminated leg at all; -1 keeps the answer PCMU-only as before.
	static std::string buildMediaSdp(const std::string& serverIp, int rtpPort,
		bool sendrecv = false, int dtmfPt = -1);

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

	// Live RFC 3261 §17 transaction counts. Exposed for host tests, which need to
	// assert the TRACKING DECISION rather than wait for a timer: tick() throttles
	// itself to 1 Hz, so a test that drives it in a loop cannot observe a 500 ms
	// Timer A at all and would pass whether or not the decision was right. Reading
	// the count instead tests the thing under test directly.
	size_t getClientTransactionCount();
	size_t getServerTransactionCount();

	// ── RFC 4733 DTMF hand-off (Issue #199 item 3) ──────────────────────────────
	//
	// Called from an RTP RECEIVE TASK, not the SIP thread. This is the only
	// public entry point on this class that does NOT expect _mutex to be held —
	// and must never take it. An RTP task blocked behind a SIP pass is audio
	// jitter on a live call, so the press is copied into a small fixed ring under
	// its own mutex and the media task returns immediately.
	//
	// The press is stamped with its arrival time here, at capture, because the
	// SIP thread may not drain for up to a tick and the inter-digit timeout has
	// to be measured against the key press rather than against the drain.
	void queueDtmfDigit(std::string_view callId, char digit);

	// Key presses discarded because the ring was full — i.e. the SIP thread fell
	// far enough behind that a digit was lost. Should sit at zero; a non-zero
	// value is a real "the user pressed a key and nothing happened" bug report.
	uint64_t dtmfDigitsDropped() const;

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

	// Voicemail (Issue #246): set/query a per-extension flag, mirroring
	// setDnd/getDndExtensions exactly except this one IS NVS-persisted (see
	// PbxFeatureConfig::setVoicemailEnabledLocked) since the toggle must
	// survive a reboot. setVoicemail is the mutating path behind
	// POST /api/voicemail.
	void setVoicemail(const std::string& extension, bool on);
	std::vector<std::string> getVoicemailExtensions();

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

	// Issue #166 (Kari's Law): the extensions alerted when 911 is dialed, plus
	// the callback number and site string the alert carries. `exts` uses the
	// same delimited member syntax as ring groups and page zones.
	void setE911Config(const std::string& exts, const std::string& callback,
		const std::string& location);
	// {notifyExts, callback, location} as configured.
	std::tuple<std::string, std::string, std::string> getE911Config();
	std::vector<std::tuple<std::string, std::string, std::string>> getRingGroups();

	// Parked calls snapshot for the TUI: {orbit, parkedExt, parker, secondsParked}.
	std::vector<std::tuple<std::string, std::string, std::string, int>> getParkedCalls();

	// Paging zones (980–989). setPageZone replaces a zone's membership; an empty
	// member list deletes the zone. Thread-safe and NVS-persisted. The getter
	// returns {zoneExt, "m1,m2,..."} pairs for the dashboard.
	void setPageZone(const std::string& zoneExt, const std::string& members);
	std::vector<std::pair<std::string, std::string>> getPageZones();

	// ── Dial plan (Issue #69, Trunk action Issue #165) ───────────────────────────
	// A bounded, ordered pattern → action rule table (see DialPlan.hpp for the
	// pattern grammar and POCKETDIAL_MAX_DIAL_RULES for the cap). setDialRule
	// upserts one rule: a rule whose pattern is already in the table is edited IN
	// PLACE, keeping its evaluation position; a new pattern is appended, and is
	// refused (logged, not applied) once the table is full. An empty `target`
	// deletes the rule with that pattern. `action` is "group" | "page" | "park" |
	// "trunk". `stripDigits` only matters for "trunk" (leading digits stripped
	// off the dialed string before prepending `target` — e.g. pattern
	// "9XXXXXXXXXX", stripDigits 1, target "1" turns "92025550123" into
	// "12025550123" and places it as an outbound call through the configured
	// anchor/telephony provider); every other action ignores it.
	//
	// The rule is validated here, not at dial time: the pattern and target must be
	// NVS/JSON-safe tokens (DialPlan.hpp's isDialTokenSafe), the target must have
	// the right shape for the action (980–989 for "page", a real orbit for
	// "park"), and reserved virtual extensions are refused as patterns. Invalid
	// input is logged and dropped — same contract as setRingGroup/setPageZone.
	//
	// Thread-safe (takes _mutex / _snapshotMutex) and NVS-persisted, exactly like
	// setRingGroup. The getter returns {pattern, action, target, stripDigits}
	// tuples in TABLE ORDER — the order rules are evaluated in — for the
	// dashboard and the API.
	void setDialRule(const std::string& pattern, const std::string& action, const std::string& target,
		int stripDigits = 0);
	std::vector<std::tuple<std::string, std::string, std::string, int>> getDialRules();

	// ── Generic ITSP SIP trunk (Issue #164) ──────────────────────────────────
	//
	// The carrier side of a "route to trunk" dial rule. With no valid config
	// the rule behaves exactly as it always has and routes to the vendor-API
	// anchor instead, so installing this is what switches a board over.
	//
	// Config::host may be a dotted quad or a name. A name is resolved off the
	// SIP thread by TrunkResolver and only the CACHE is consulted when a call
	// is placed, so the first call after a config change can be refused with
	// 503 while the first resolution completes. A literal is answered directly
	// and is the common static-IP-trunk case.
	void setTrunkConfig(const SipTrunk::Config& cfg);
	SipTrunk::Config getTrunkConfig();

#if !defined(ESP_PLATFORM) && !defined(ESP32) && !defined(ARDUINO)
	// Test-only. Gated because these three are DEFINED OUT OF LINE, in
	// RequestsHandler.cpp -- and that, not the gate, is what decides whether a
	// test accessor reaches the firmware image:
	//
	//   defined out of line in a .cpp : the TU always emits the symbol. It
	//       ships unless something removes it. --gc-sections may or may not
	//       collect it; do not rely on that.
	//   defined inline in this header : never emitted at all when nothing
	//       calls it, because an unused inline member function generates no
	//       code. Gating it is harmless but buys nothing.
	//
	// Worth stating plainly because the earlier version of this comment said
	// these get "the same treatment the anchor/CDR/registrar accessors above
	// already get", which invites the wrong conclusion. Those are gated AND
	// inline, so their gate is belt-and-braces; the ~nine ungated voicemail
	// accessors further down are inline too, and are already absent from the
	// image -- verified against the link map, 0 kept and 0 discarded, not
	// assumed. Neither group is evidence that gating is what keeps a test
	// accessor out of firmware.
	//
	// So: if you add an accessor here, either define it inline below and the
	// question does not arise, or define it in the .cpp and keep it inside
	// this guard. Checking `nm`/the link map beats reasoning about it.
	//
	// The one that makes this worth caring about rather than tidy is
	// expireTrunkDeadlinesForTest(): it forces every live trunk dialog past
	// its deadline, so shipping it would put "hang up every call in progress"
	// inside anything that can reach the handler.

	// How many of the POCKETDIAL_MAX_TRUNK_CALLS relay pairs are in use. A pair
	// is two cross-wired RtpReceivers; this is the only external view of that,
	// and it is what a test asserts against to show a teardown really released
	// the media rather than only answering the signalling.
	size_t trunkRelaysInUseForTest();

	// Age every live trunk dialog past its deadline, so one tick() exercises
	// the no-answer path without a 60-second test.
	void expireTrunkDeadlinesForTest();

	// What the resolver currently knows about the configured SBC host. Refused
	// means nothing is known and nothing is in flight; anything else means a
	// resolution has at least been ASKED FOR, which is what proves tick()
	// primes the cache rather than leaving an FQDN trunk permanently dead.
	TrunkResolver::Status trunkResolveStatusForTest();
#endif

	// ── Telephony-API credential slots (ported from drawbridge) ──────────────────
	// TelephonyApiConfig.hpp owns validation + NVS/file persistence for the
	// bounded kSlots-entry credential table; RequestsHandler owns the instance
	// (_tapiConfig below) and serializes access under _mutex, per that header's
	// documented threading contract. Unlike the DND/forward/ring-group/dial-plan
	// getters above, these read _tapiConfig directly under _mutex rather than
	// through the lock-free dashboard snapshot: nothing on the SIP hot path
	// reads this table yet (boot-time active-slot selection is a later, separate
	// task — see TelephonyApiConfig.hpp's class comment), so there is no
	// hot-path contention to shield HTTP-thread reads from.
	//
	// getTelephonyConfigSlots() returns all kSlots display-safe views (secrets
	// masked to secretSet, per SlotView's contract) for GET /api/telephony-config;
	// getTelephonyConfigSlot() returns just one (out-of-range -> a default view,
	// same as TelephonyApiConfig::view()). setTelephonyConfigSlot() is the mutating
	// path behind PUT /api/telephony-config/<slot> ("" on success, else a short
	// operator-facing error); setTelephonyConfigActiveSlot() backs
	// POST /api/telephony-config/<slot>/activate. clearTelephonyConfigSlot()
	// backs DELETE /api/telephony-config/<slot> (wipes just that one slot);
	// clearAllTelephonyConfig() backs /api/factory-reset (wipes every slot
	// and the active-slot selection) -- see TelephonyApiConfig::clearAll().
	std::vector<TelephonyApiConfig::SlotView> getTelephonyConfigSlots();
	TelephonyApiConfig::SlotView getTelephonyConfigSlot(size_t idx);
	std::string setTelephonyConfigSlot(size_t idx, const TelephonyApiConfig::Slot& s, bool keepSecret);
	std::string setTelephonyConfigActiveSlot(size_t idx);
	std::string clearTelephonyConfigSlot(size_t idx);
	std::string clearAllTelephonyConfig();

	// ── SBC mode (Issue #201) ─────────────────────────────────────────────────
	// {enabled, route}. See PbxFeatureConfig::setSbcMode()'s doc comment for
	// what `route` does and does not do.
	std::pair<bool, size_t> getSbcMode();
	// Orchestrates across both config classes: enabling (or changing route
	// while already enabled) first validates+activates the slot through
	// TelephonyApiConfig (same path as POST /api/telephony-config/<n>/activate
	// — "" on success, else that call's "Bad slot index" style error, in which
	// case SBC mode is left exactly as it was). Disabling never touches the
	// active slot: some other feature (the 555 anchor extension, a manual
	// Trunk dial-plan rule) may still depend on it.
	std::string setSbcMode(bool enabled, size_t route);

	// Connectivity probe for the dashboard's "Test Dial" action (not a real
	// bridged call — no SIP session, no MediaBridge, no caller): self-dials
	// the currently-active slot's own routeDn through _anchorClient and
	// immediately drops it, reporting only whether the carrier accepted the
	// makeCall(). `idx` must name the currently-active slot (the only one with
	// a live, boot-selected _anchorClient — see anchorIsSynchronous()'s doc
	// comment on why provider selection is boot-time-only); any other slot
	// returns ok=false with an explanatory error, never silently tests the
	// wrong slot. Deliberately does NOT hold _mutex across the anchor calls
	// themselves: for a real (non-Loopback) provider these are blocking TLS
	// HTTP round trips, and holding the engine's one shared mutex across that
	// would stall SIP packet handling for the whole device, not just this HTTP
	// request. Safe to call from the HTTP handler thread.
	struct TestDialResult
	{
		bool ok = false;
		std::string participantId;
		std::string error;
	};
	TestDialResult testDialSlot(size_t idx);

	// ── DID -> extension inbound routing (new) ────────────────────────────────────
	// DidMapping.hpp owns the bounded table + field validation; RequestsHandler
	// owns the instance (_didMapping below) and serializes access under _mutex,
	// same pattern and same rationale (no hot-path reader yet — see
	// DidMapping.hpp's BOUNDARY comment) as the Telephony-API slots above.
	// getDidMappings() backs GET /api/did-mapping; setDidMapping()/
	// removeDidMapping() back PUT/DELETE respectively ("" on success, else a
	// short operator-facing error — removeDidMapping is idempotent, so it is
	// always ""). clearAllDidMappings() backs /api/factory-reset (wipes the
	// whole table) -- see DidMapping::clearAll().
	std::vector<DidMapping::Entry> getDidMappings();
	std::string setDidMapping(const std::string& did, const std::string& extension);
	std::string removeDidMapping(const std::string& did);
	std::string clearAllDidMappings();

	// Backs /api/factory-reset: wipes the CDR ring (caller/callee history is
	// as sensitive as the credential tables above and lives in its own NVS
	// namespace, "cdrlog" — see CdrRing::clearAll()).
	void clearAllCallHistory();

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

#if !defined(ESP_PLATFORM) && !defined(ESP32) && !defined(ARDUINO)
	// Test-only: redirect the Telephony-API / DID-mapping host-file stores to
	// test-specific paths and reload from them. Without this every test that
	// constructs a RequestsHandler and exercises PUT /api/telephony-config or
	// PUT/DELETE /api/did-mapping would read and write the SAME default files
	// ("pocketdial_tapi.cfg"/"pocketdial_didmap.cfg" in the process's cwd) as
	// every other test in the binary — order-dependent failures and state that
	// leaks into the next run. Mirrors TelephonyApiConfig_test.cpp's/
	// DidMapping_test.cpp's own setStorePath() fixture pattern. Not compiled
	// into device firmware (NVS has no such notion of a "path" to redirect).
	void setTelephonyStorePathsForTest(const std::string& tapiPath, const std::string& didmapPath)
	{
		_tapiConfig.setStorePath(tapiPath);
		_tapiConfig.load();
		_didMapping.setStorePath(didmapPath);
		_didMapping.load();
	}

	// Test-only: seed one CDR record directly (bypassing a real call flow) and
	// read the ring back, so a factory-reset test can assert clearAllCallHistory()
	// actually empties it without driving a full INVITE/BYE sequence just to
	// produce one record. Not compiled into device firmware.
	void recordCallForTest(const std::string& src, const std::string& dest)
	{
		std::lock_guard<std::mutex> lock(_mutex);
		_cdr.record(nullptr, src, dest);
	}
	std::vector<CallDetailRecord> cdrSnapshotForTest()
	{
		std::lock_guard<std::mutex> lock(_mutex);
		return _cdr.snapshot();
	}
	// Test-only: live DTMF accumulators, so a teardown path can be checked for
	// actually routing through endCall() (which forgets the dialog's digits)
	// rather than only erasing the session (issue #228).
	size_t dtmfAccumulatorCountForTest()
	{
		std::lock_guard<std::mutex> lock(_mutex);
		return _dtmf.accumulatorCount();
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

	// Test-only: the boot-selected anchor client (Loopback in every host test),
	// so a test can read LoopbackAnchorClient::lastMakeCallDestination() and
	// prove a dial-plan Trunk rule's transform actually reached makeCall() —
	// see that accessor's comment. Not compiled into device firmware.
	AnchorClient* anchorClientForTest() { return _anchorClient; }

	// Test-only: directly inject an adopted device into the registrar without an ARP lookup.
	void adoptDeviceForTest(const std::string& mac, const std::string& ext, Registrar::DeviceState state = Registrar::DeviceState::Learned)
	{
		std::lock_guard<std::mutex> lock(_mutex);
		_registrar.adoptDeviceForTest(mac, ext, state);
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

	// Issue #218: onReinvite()/onUpdate() share this for the anchored-media
	// (555) leg. The board built the ORIGINAL 200 OK for that leg itself
	// (originateAnchorCall()/onAnchorInvite()) rather than relaying one, so a
	// re-INVITE/UPDATE here is something to ANSWER, not something with no
	// peer to relay to -- unlike the 777/888 legs, which genuinely have none.
	// Before this, all three fell into the same 488 refusal, which meant a
	// phone could never hold an anchored/trunk call at all (confirmed on
	// hardware: the far end heard silence, not hold music, because the hold
	// itself was never accepted). Answers with the SAME media (codec/port
	// unchanged -- the RTP session between phone and board never stops) and
	// toggles the owning MediaBridge's held state, which decides whether the
	// anchor hears the handset or hold music; the SDP negotiation itself
	// doesn't need to change shape to do that. Returns false only when no
	// bridge exists for this Call-ID (a race with teardown), in which case
	// the caller has already sent a 481 and should just return.
	bool answerAnchorReinvite(const std::shared_ptr<SipMessage>& data,
		const std::shared_ptr<Session>& session, const std::shared_ptr<SipClient>& src);

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
	// Issue #166 part 2: Kari's Law on-site notification. A sibling machine
	// reaching the engine only through PbxEnv, so it adds one member and one
	// call rather than more surface to this file.
	EmergencyNotifier _e911Notifier{*this};

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
	void freeTransactionsForCallId(std::string_view callId) override
	{
		_txLayer.freeForCallId(callId);
	}
	void log(std::string msg, bool isError = false) override
	{
		queueLog(std::move(msg), isError);
	}
	const std::string& localIp() const override { return _localIp; }
	int serverPort() const override { return _serverPort; }
	std::shared_ptr<SipClient> findRegistered(std::string_view number) override
	{
		// THE routing choke point. Every path that asks "can a call go to this
		// name" comes through here — CallForker (blind transfer, CFU/CFB/CFNA,
		// ring-group members, dial-plan targets), CallPickup, ParkOrbit,
		// DtmfFeatureCodes — which is precisely why Issue #202 extends this one
		// function instead of teaching each caller about service extensions
		// separately. That divergence is what produced #197/#198.
		//
		// Order matters: a REGISTERed phone always wins. A service name can never
		// be registered (onRegister refuses it), so the two sets are disjoint and
		// the fallback only ever runs on a miss.
		auto c = findClient(number);
		if (c.has_value()) return c.value();
		return findServicePeer(number);
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
	// A dial-plan "route to trunk" action. Prefers a configured generic SIP
	// trunk (#164); with none configured this is the vendor-API anchor path it
	// has always been, unchanged.
	bool routeTrunkCall(const std::shared_ptr<SipMessage>& data,
		const std::shared_ptr<SipClient>& caller, const std::string& destination) override;

	// ── SipTrunk::Listener (Issue #164) ──────────────────────────────────────
	// Called synchronously on the SIP thread with _mutex already held, from
	// inside SipTrunk::handleResponse()/sweep(). See SipTrunk::Listener for the
	// ordering guarantees each one carries.
	void onTrunkRinging(const SipTrunk::TrunkEvent& ev, bool earlyMedia) override;
	void onTrunkAnswered(const SipTrunk::TrunkEvent& ev,
		const std::shared_ptr<SipMessage>& ok) override;
	void onTrunkFailed(const SipTrunk::TrunkEvent& ev, int status) override;
	void onTrunkRemoteBye(const SipTrunk::TrunkEvent& ev) override;

	// A relay pair is free when NEITHER receiver is active. Scanned rather than
	// tracked with a flag, the same shape the voicemail slot scan settled on:
	// the receivers are the real resource, so asking them directly cannot drift
	// out of step with a bookkeeping bool the way a flag can.
	int  findFreeTrunkRelay() const;

	// Stop both receivers of a pair and drop their raw wiring. Idempotent, and
	// safe on a slot that was never started -- endCall() is the ONE place this
	// runs, for every teardown path, which is the #246 lesson applied here
	// rather than relearned.
	void releaseTrunkRelay(int slot);

	// Refuse a still-ringing trunk call on its retained INVITE, mapping the
	// carrier's status onto one the handset should see. Mirrors
	// refuseRingingAnchor(), including the rule that endCall() never sends a
	// final response itself.
	void refuseRingingTrunk(const std::string& callId, int carrierStatus);

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

	// Stamps Allow / Supported / Accept / Allow-Events onto an outgoing response
	// (issue #199 root cause 2). The lists are compiled from initHandlers() and
	// are deliberately conservative — see the comment block above the definition
	// in RequestsHandler.cpp for why "timer" and "100rel" are NOT claimed.
	//
	// Currently called only from onOptions(), the capability-discovery method.
	// The server-terminated INVITE responses (777 echo, 440 tone, 888 conference,
	// 555 anchor, park ring-back, and CallForker's group 180s) each build their
	// own 180/200 and would each need their own call; the ordinary call path
	// RELAYS the far phone's 180/200 and must keep advertising that phone's
	// capabilities, not ours. Adding those is a per-site follow-up, not a
	// one-line sweep.
	void addCapabilityHeaders(SipMessage& response) const;

	// Call parking / park-orbit: the orbit FSM lives in ParkOrbit (see
	// ParkOrbit.hpp). Guarded by _mutex.
	ParkOrbit _park{*this};

	// Music on hold for parked callers (issue #162), and — via setHoldMusic()
	// at _mediaBridges' wiring below — for a held anchor/trunk call (issue
	// #218). Owned here and attached to both at construction; silent hold is
	// the fallback when no clip is loaded, so this being idle is a normal
	// state rather than a fault. Declared BEFORE _mediaBridges below on
	// purpose: ~MediaBridge() (via stopBridge()) may call _moh->removeTap(),
	// so this must still be alive when _mediaBridges is destroyed — same
	// reverse-declaration-order reasoning as the comment on _mediaBridges
	// itself.
	HoldMusic _holdMusic;

	// The single in-flight MoH preview dialog. Server-originated, so there is no
	// Session backing it — it is matched by Call-ID exactly like the register beep
	// and the park ring-back. Guarded by _mutex like every other engine member.
	struct MohPreview
	{
		bool        active = false;
		std::string callId;        // full "Call-ID: ..." line, as the wire carries it
		std::string extension;
		std::string fromTag;
		std::string branch;
		std::string toTag;         // learned from their 200 OK, needed for the BYE
		sockaddr_in addr{};
		int         listener = -1; // HoldMusic listener id once they answer
	};
	MohPreview _mohPreview;
	// True when callID is the MoH preview's own dialog. Mirrors
	// RegisterBeeper::ownsCallID: both are server-originated UACs with no
	// Session, so response handlers must recognise them explicitly or fall
	// through to endHandle() and answer the phone with a stray 404.
	bool mohPreviewOwnsCallID(std::string_view callID) const
	{
		return _mohPreview.active && callID == _mohPreview.callId;
	}

	// Claim a response/request for the preview dialog. Both return true when the
	// message belonged to the preview and was fully handled.
	// All three assume _mutex is ALREADY held: the handle* pair runs inside
	// handle()'s lock, and stopMohPreviewLocked() is shared by the public
	// stopMohPreview() and by startMohPreview()'s replace-the-previous path.
	// _mutex is not recursive, so mixing the two would self-deadlock.
	bool handleMohPreviewOk(const std::shared_ptr<SipMessage>& data);
	bool handleMohPreviewFailure(const std::shared_ptr<SipMessage>& data);
	bool handleMohPreviewEnd(const std::shared_ptr<SipMessage>& data);
	void stopMohPreviewLocked();
	void releaseMohPreviewLocked();

public:
	// Load a music-on-hold clip and begin the pacing stream. Called after the SD
	// card is mounted, since that is where the clip lives. Returns false when the
	// file is missing or is not 8 kHz mono µ-law — a false here is NOT fatal and
	// must not fail the boot: park simply keeps its silent hold.
	//
	// Clip format is the wire format itself (WAVE_FORMAT_MULAW, 8 kHz, mono), so
	// playback is a memcpy rather than a decode. Prepare one with:
	//     ffmpeg -i music.mp3 -ar 8000 -ac 1 -acodec pcm_mulaw moh.wav
	bool startHoldMusic(const std::string& clipPath);

	// Dashboard/status accessors.
	bool     holdMusicLoaded()  const { return _holdMusic.isLoaded(); }
	unsigned holdMusicSeconds() const { return _holdMusic.clipSeconds(); }
	unsigned holdMusicListeners() const { return _holdMusic.listenerCount(); }

	// ── MoH preview: ring an extension and play the hold clip to it ────────────
	// "Does my hold music sound right?" is otherwise answered by parking a real
	// call, which needs two phones and a caller willing to be put on hold. This
	// rings one extension directly from the dashboard and streams the clip when
	// they answer.
	//
	// Server-originated UAC dialog, the same shape as the park ring-back
	// (ParkOrbit::ringBackParker) and the register beep: a minted Call-ID/From-tag
	// recognised before the normal session lookup, with no Session allocated.
	//
	// ONE preview at a time. A second request replaces the first, because the
	// realistic misuse is an operator clicking the button twice, not two operators
	// previewing at once — and leaving an orphaned ringing dialog is worse than
	// cancelling it.
	//
	// Returns false if no clip is loaded, the extension is not registered, or the
	// message pool refused. Never throws, never blocks.
	bool startMohPreview(const std::string& extension);

	// Hang up an in-progress preview. Safe when none is running.
	void stopMohPreview();

	// Extension the preview is ringing/playing to, or empty when idle.
	// Not const: it takes _mutex, which is not declared mutable.
	std::string mohPreviewExtension();

private:

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

	// Blind transfer (RFC 3515 §2 / RFC 5359 §2.4), issue #197: onRefer() moves the
	// TRANSFEREE — the party that is not the transferor — to the target, and drops
	// the transferor. Because media is peer-to-peer, that is a two-dialog B2BUA
	// operation: a new server-originated leg carries the transferee's SDP to the
	// target, and the transferee's own dialog survives untouched until the target
	// answers. These two claim every response on that new leg, ahead of the normal
	// session paths (same pattern as _beeper.handleOk()/handleInviteFailure()),
	// because the server is its UAC and the transferee is not in that dialog at all:
	//
	//   handleBlindXferOk      — target answered: ACK it, re-INVITE the transferee
	//                            with the target's SDP (the swap that completes the
	//                            transfer), and link the two Call-IDs as a bridge.
	//   handleBlindXferFailure — target refused: ACK the non-2xx in its own
	//                            transaction, then release the transferee, who has
	//                            nobody left on either side.
	//
	// Both return false for any message that is not on such a leg. Caller holds
	// _mutex.
	bool handleBlindXferOk(const std::shared_ptr<SipMessage>& data);
	bool handleBlindXferFailure(const std::shared_ptr<SipMessage>& data);

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

	// ── Voicemail deposit: answer locally as voicemail (Issue #246) ──────────────
	// Called from the CFNA sweep (tick()) and onBusy()'s CFB path when the
	// diverting extension has no explicit forward target but has voicemail
	// enabled -- NOT from onInvite()'s virtual-extension dispatch, since this
	// is a fallback for an ALREADY-RETAINED invite mid-call, not a fresh dial.
	// `invite` is the retained original INVITE, `src` its caller, `extension`
	// the mailbox owner (the extension that didn't answer / was busy). Finds
	// a free slot in the voicemail leg pool and answers with a real sendrecv
	// SDP (888-style: buildMediaSdp(), not the 777 echo pattern, which never
	// actually terminates media on the board -- see #194); 486 Busy Here if
	// every leg is busy (matches 888's full-room refusal), 503 only for
	// message-pool/session-pool exhaustion. Caller holds _mutex.
	void answerVoicemailDeposit(const std::shared_ptr<SipMessage>& invite,
		const std::shared_ptr<SipClient>& src, const std::string& extension);
	// Shared by answerVoicemailDeposit() and answerVoicemailRetrieval(): the
	// RTP pair's isActive() is the ground truth for "in use" regardless of
	// VoicemailLeg's own state (see answerVoicemailDeposit()'s call site for
	// why leg state alone was wrong). Two more busy signals must ALSO be
	// clear, both found in review (Fable-Low): _vmFlushBusy (a slot whose
	// deposit just hung up looks RTP-free immediately, but its staging
	// buffer may still be mid-fwrite on the writer task) and
	// _vmSdJobState != Idle (a retrieval leg's list/read/delete job may
	// still be in flight even after the caller hangs up -- see
	// VmSdJob::callId's doc comment on why releaseVoicemailLeg() never
	// resets job state itself). Returns -1 if every leg is busy any way.
	int findFreeVoicemailSlot() const;
	// Stop the leg's RTP receiver/sender and return it to Idle. Called from
	// endCall()'s voicemail safety net, covering every teardown path.
	void releaseVoicemailLeg(int slot, const std::string& callId);
	// tick()'s 1Hz voicemail sweep: advances a Deposit leg from PlaybackDone
	// (greeting finished) to Recording, and BYEs + tears down any voicemail
	// session whose wall-clock deadline has expired (see Session::
	// armVoicemailDeadline()'s doc comment for why this exists alongside
	// onCallerRtp()'s byte-cap). Caller holds _mutex.
	void sweepVoicemailLegs(std::chrono::steady_clock::time_point now);
	// Finalize whatever `_vmLegs[slot]` recorded (stopRecording() is a no-op
	// if it wasn't Recording), copy it into that slot's staging buffer, and
	// push a QueuedRecording -- called from endCall()'s voicemail safety net,
	// BEFORE releaseVoicemailLeg() resets the leg. Drops (does not enqueue)
	// a zero-length recording -- nobody said anything, nothing to flush.
	void enqueueVoicemailFlush(int slot);

	// ── Voicemail retrieval: ext 796 dial-in (Issue #246, slice 3/3) ────────
	// Called from onInvite()'s virtual-extension dispatch (unlike
	// answerVoicemailDeposit(), this IS a fresh dial, not a mid-call
	// fallback). No PIN for MVP: the mailbox is src's OWN extension,
	// authenticated purely by Caller-ID -- an accepted tradeoff documented
	// in pocket_dial_246_voicemail.md, fine for a LAN-only extension,
	// revisit if 796 ever becomes trunk-reachable. Claims a free slot the
	// same way answerVoicemailDeposit() does, answers with a real sendrecv
	// SDP, arms RFC 4733 DTMF into this leg's own digit slot (never the
	// global accumulator -- see _vmPendingDigit's doc comment), and kicks
	// off the initial mailbox-listing SD job. VoicemailLeg itself stays
	// Idle throughout the "answered, list not back yet" window --
	// _vmSdJobState going Pending IS the busy signal for this slot; no new
	// VoicemailLeg state was needed. Caller holds _mutex.
	void answerVoicemailRetrieval(const std::shared_ptr<SipMessage>& invite,
		const std::shared_ptr<SipClient>& src);
	// One slot's worth of runVoicemailSdJobs() below -- a no-op unless
	// _vmSdJobState[slot] is Pending. Runs delete-then-list-then-read as
	// the job struct flags, against `source`, then stores Done. Never
	// touches _vmMenus[slot] or dispatches anything -- purely the I/O half;
	// sweepVoicemailLegs()/handleVoicemailSdJobDone() do the consuming, on
	// the SIP thread, once Done is observed under acquire ordering.
	void runVoicemailSdJob(int slot, vmarchive::Source& source);
	// sweepVoicemailLegs()'s Retrieval-purpose branch, factored out for
	// readability: a List job going Done starts the menu (start()); a Read
	// job going Done starts real playback via VoicemailLeg::startPlaying()
	// directly (bypassing dispatchVoicemailMenuCommand() -- there is
	// nothing left to dispatch once the bytes are in hand) and re-arms the
	// deadline for this message (advisor review: per-message, not once at
	// answer, or a long inbox would hit the deadline mid-playback of an
	// early message). A failed Read (message vanished under us) is treated
	// as end-of-mailbox rather than getting stuck silent.
	//
	// Returns true if the call should be torn down. NEVER calls
	// endCall()/sendVoicemailBye() itself -- every caller of this function
	// runs from inside sweepVoicemailLegs()'s live iteration over
	// _sessions (an unordered_map), and erasing the CURRENT element mid-
	// range-for is undefined behavior. The caller queues the callID into
	// the SAME deferred toExpire list the wall-clock deadline check uses,
	// processed only after that iteration completes.
	bool handleVoicemailSdJobDone(int slot, const std::string& callID,
		const std::shared_ptr<Session>& session);
	// Turns one VoicemailMenu::Result into action: builds and queues an SD
	// job when playIndex and/or deleteIndex call for one (both checked
	// independently -- Fable-Low review: a single digit event can require
	// both), resets the leg FIRST when a new Read is about to be requested
	// (advisor review, point 3: the leg may still be Playing the OLD
	// message when a digit interrupts it -- fillTx() checking state under
	// its own mutex is what makes reusing _vmRecordBufs[slot] safe here,
	// NOT any assumption that RtpSender::stop() blocks, which it does not
	// on ESP). PlayPrompt has no asset in this MVP -- synthesizes an
	// immediate onPlaybackDone() the same way the deposit-side greeting
	// degrades when unloaded.
	//
	// Returns true on Command::Hangup -- see handleVoicemailSdJobDone()'s
	// doc comment for why this never tears the call down itself either. A
	// Hangup MAY also have queued a delete-only SD job in the same call
	// (deleting the last message before hanging up); that's safe to leave
	// running after teardown, since a delete-only job never touches
	// _vmRecordBufs[slot] -- the orphan sweep at the top of
	// sweepVoicemailLegs() reclaims the slot once it finishes.
	bool dispatchVoicemailMenuCommand(int slot, const std::string& callID,
		const std::shared_ptr<Session>& session, const VoicemailMenu::Result& r);
	// The BYE-then-teardown steps sweepVoicemailLegs()'s deadline-expiry
	// path already used, factored out so its own toExpire loop is the only
	// caller -- see dispatchVoicemailMenuCommand()'s doc comment for why a
	// menu-driven hangup must go through that SAME deferred list instead of
	// calling this directly.
	void sendVoicemailBye(const std::string& callID, const std::shared_ptr<Session>& session);

public:
	// Drains whatever is currently queued to `sink`, reading each recording
	// from this instance's own staging buffers. The ESP+PD_ETH_HAS_SD writer
	// task (spawned in the constructor) calls this against
	// vmarchive::productionSink() in a loop; a host test calls it directly
	// against a FakeSink, exercising the identical vmarchive::drainAll() path
	// with no writer task needed.
	void drainVoicemailFlush(vmarchive::Sink& sink)
	{
		vmarchive::drainAll(_vmFlushQueue, sink, _vmStagingBufs,
			[this](const vmarchive::QueuedRecording& rec) {
				if (rec.stagingSlot >= 0 && rec.stagingSlot < static_cast<int>(POCKETDIAL_MAX_VOICEMAIL_LEGS))
				{
					// See _vmFlushBusy's doc comment: this is the one moment
					// the staging buffer is provably safe to reuse again.
					_vmFlushBusy[rec.stagingSlot].store(false, std::memory_order_release);
				}
			});
	}
	size_t voicemailFlushQueueDepthForTest() const { return _vmFlushQueue.size(); }
	// Runs every slot's pending retrieval SD job (list/read/delete), a
	// no-op for any slot not Pending. The ESP+PD_ETH_HAS_SD writer task
	// (spawned in the constructor, same task drainVoicemailFlush() above
	// already runs on) calls this against vmarchive::productionSource() in
	// its loop; a host test calls it directly against a FakeSource,
	// exercising the identical per-slot runVoicemailSdJob() path with no
	// writer task needed -- same public-for-the-lambda reasoning as
	// drainVoicemailFlush() above (a plain xTaskCreatePinnedToCore callback
	// is not a member function and cannot reach a private method).
	void runVoicemailSdJobs(vmarchive::Source& source)
	{
		for (size_t i = 0; i < POCKETDIAL_MAX_VOICEMAIL_LEGS; ++i)
		{
			runVoicemailSdJob(static_cast<int>(i), source);
		}
	}
	// Test-only seam, same reasoning as RtpReceiver::dispatchDtmf() being
	// public "so host tests can reach it": RtpReceiver::start() is a no-op
	// stub on EVERY host build (WSL/Linux included -- see RtpReceiver.cpp's
	// `#else` host-stub branch), so nothing can otherwise get caller audio
	// into an active leg. `slot` comes from Session::getVoicemailLegSlot()
	// on the session a test just answered.
	bool feedVoicemailAudioForTest(int slot, const uint8_t* mulaw, size_t n)
	{
		if (slot < 0 || slot >= static_cast<int>(POCKETDIAL_MAX_VOICEMAIL_LEGS)) return false;
		return _vmLegs[slot].onCallerRtp(mulaw, n);
	}
	// Test-only counterpart to feedVoicemailAudioForTest(): reads what the
	// leg would send the caller right now (a greeting/prompt frame, or false
	// if not Playing).
	//
	// UNLIKE RtpReceiver, RtpSender is REAL on a WSL/Linux host build (#82's
	// Linux media path spins an actual std::thread pacer -- see
	// RtpSender.cpp's `__linux__` branch), and it calls this same leg's
	// fillTx() on its own 20 ms schedule the instant answerVoicemailDeposit()
	// starts it -- before this seam's caller gets a chance to. A test that
	// calls this synchronously right after answering a Playing leg is
	// racing that thread for the clip and MUST NOT assert on winning that
	// race (see VoicemailDivert.DepositPlaysGreetingBeforeRecordingWhenOneIsLoaded's
	// fix history) -- poll voicemailLegStateForTest() for PlaybackDone
	// instead of asserting this call succeeds on the first try.
	bool readVoicemailPlaybackForTest(int slot, uint8_t* out, size_t count)
	{
		if (slot < 0 || slot >= static_cast<int>(POCKETDIAL_MAX_VOICEMAIL_LEGS)) return false;
		return _vmLegs[slot].fillTx(out, count);
	}
	// Test-only: the leg's own state, for polling past the RtpSender race
	// described above (e.g. "wait for PlaybackDone") without touching
	// fillTx()/onCallerRtp() and perturbing the very state being observed.
	VoicemailLeg::State voicemailLegStateForTest(int slot) const
	{
		if (slot < 0 || slot >= static_cast<int>(POCKETDIAL_MAX_VOICEMAIL_LEGS))
			return VoicemailLeg::State::Idle;
		return _vmLegs[slot].state();
	}
	// Test-only: deliver one DTMF digit to a retrieval leg exactly the way
	// the real RtpSink lambda in answerVoicemailRetrieval() does (same
	// "deaf during I/O" check) -- RFC 4733 reception is unreachable on
	// host for the same no-real-socket reason feedVoicemailAudioForTest()
	// exists.
	void feedVoicemailDigitForTest(int slot, char digit)
	{
		if (slot < 0 || slot >= static_cast<int>(POCKETDIAL_MAX_VOICEMAIL_LEGS)) return;
		if (_vmSdJobState[slot].load(std::memory_order_acquire) == VmSdJobState::Idle)
		{
			_vmPendingDigit[slot].store(digit, std::memory_order_release);
		}
	}
	// Test-only: is a retrieval SD job currently in flight for this slot?
	// (list/read/delete just requested, result not consumed yet.)
	bool voicemailSdJobPendingForTest(int slot) const
	{
		if (slot < 0 || slot >= static_cast<int>(POCKETDIAL_MAX_VOICEMAIL_LEGS)) return false;
		return _vmSdJobState[slot].load(std::memory_order_acquire) == VmSdJobState::Pending;
	}
	// Test-only: how many messages the last completed List job found for
	// this slot (0 before any List job has completed).
	size_t voicemailMessageCountForTest(int slot) const
	{
		if (slot < 0 || slot >= static_cast<int>(POCKETDIAL_MAX_VOICEMAIL_LEGS)) return 0;
		return _vmMessageCounts[slot];
	}
	// Test-only: runs sweepVoicemailLegs() directly, bypassing tick()'s 1Hz
	// self-throttle (see pocket_dial_build_environment.md's "host tests
	// can never see a SIP timer" note). A retrieval test needs several
	// separate sweep passes -- list done, read done, playback done, digit
	// -- each a genuine advisor-recommended round trip through
	// runVoicemailSdJobs() in between, all faster than real wall-clock
	// time allows through tick() alone. sweepVoicemailLegs() already takes
	// `now` as a parameter rather than reading the clock itself, so this
	// seam changes nothing about what it does -- only how often a test can
	// ask it to run.
	//
	// Found while writing the first retrieval integration test: calling
	// sweepVoicemailLegs() alone is NOT enough -- tick() also drains
	// _outbox (via drainOutbox(), which does retransmit tracking + PCAP
	// capture too) and _logQueue and hands each to _onHandled()/std::cout
	// afterward. Without mirroring that here, a BYE sendVoicemailBye()
	// queues into _outbox sits there invisibly forever (or until some
	// LATER tick()/handle() call happens to flush it) -- this seam must
	// reproduce that whole flush, not just the sweep itself.
	void sweepVoicemailLegsForTest()
	{
		sweepVoicemailLegs(std::chrono::steady_clock::now());
		auto localOutbox = drainOutbox();
		auto localLogs = std::move(_logQueue);
		_logQueue.clear();
		for (const auto& log : localLogs)
		{
			if (log.first) std::cerr << log.second << '\n';
			else std::cout << log.second << '\n';
		}
		for (auto& event : localOutbox)
		{
			_onHandled(event.first, std::move(event.second));
		}
	}
	// Test-only: inject a greeting clip without a real filesystem at
	// /sdcard/vm/greeting.wav (which doesn't exist on host, or exist as a
	// portable path at all). `clip` must outlive the handler -- tests pass a
	// static/local buffer that does. Pass nullptr/0 to restore "no greeting".
	void setVoicemailGreetingForTest(const uint8_t* clip, size_t len)
	{
		if (_vmGreetingClipOwned)
		{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
			heap_caps_free(_vmGreetingClip);
#else
			std::free(_vmGreetingClip);
#endif
		}
		_vmGreetingClip = const_cast<uint8_t*>(clip);
		_vmGreetingClipLen = len;
		_vmGreetingClipOwned = false;
	}

private:

	// The shared meet-me room, created lazily on the first 888 dial-in — a MixBus and
	// its per-leg rings are ~50 KB, too much to pay at boot on a node that may never
	// hold a conference. Null until then. Caller holds _mutex.
	std::unique_ptr<ConferenceRoom> _conference;

	// ── Anchored media: virtual extension 555 (bridge to an AnchorClient) ────────
	// onInvite() routes a dial of 555 here — the docs/FEATURE_ROADMAP.md "Anchored
	// media (opt-in, unwired)" extension point, now wired into call routing.
	// AnchorClient/MediaBridge/TelephonyProvider are all vendor-neutral; pocket-dial
	// ships two concrete providers, LoopbackAnchorClient (the safe on-box default)
	// and TelephonyAnchorClient (a real WAN-anchor client, ported from drawbridge —
	// see TelephonyProvider.hpp's class comment). Chosen as a dedicated reserved
	// virtual extension — matching the established 777/440/888/999 style — rather
	// than a trunk-access prefix or an unregistered-number fallback: there is no
	// dialed destination digit string to carry (see onAnchorInvite()'s comment on
	// the makeCall() `destination` argument), so a fixed feature code is the
	// natural fit, and unlike a bare "unregistered falls through to the anchor"
	// rule it can never collide with — or silently start bridging — a mistyped
	// real extension. onAnchorInvite() itself branches on anchorIsSynchronous():
	// Loopback answers synchronously exactly as before; a real anchor rings, then
	// completes asynchronously via asyncMakeCall()/the CallEvent callback. Caller
	// holds _mutex.
	void onAnchorInvite(std::shared_ptr<SipMessage> data, const std::shared_ptr<SipClient>& caller);

	// The shared core of onAnchorInvite(), parameterized by the outbound
	// destination digit string. onAnchorInvite() calls this with the caller's
	// own number (555 has nothing dialed after it); routeTrunkCall() (Issue
	// #165's dial-plan Trunk action) calls this with the dial-plan-transformed
	// PSTN number instead, so a Trunk rule reaches the exact same
	// Loopback-sync / real-anchor-async branches 555 does. Returns true iff it
	// took ownership of the INVITE (sent some final/provisional response, or
	// dispatched an async makeCall) — false ONLY when the anchor isn't
	// connected AND respondIfDisconnected is false, so the caller (routeTrunkCall)
	// can fall through to its own 404 instead of getting two responses to one
	// INVITE. onAnchorInvite() always passes respondIfDisconnected=true. Caller
	// holds _mutex.
	// Issue #166: route a recognised 911/933 dial. Called from onInvite's
	// emergency intercept, which runs ahead of every operator-configurable
	// destination lookup so no ring group or dial-plan rule can shadow or rewrite
	// it (see EmergencyCall.hpp). Hands the trunk the BARE emergency number even
	// when the user dialed a trunk-access digit first, and owns the failure
	// response itself -- a 503, never a 404, per RFC 4497 8.3.1. Caller holds
	// _mutex.
	// Issue #166 part 2: fire the Kari's Law notification. Called ONLY after
	// the emergency call leg (or its 503) has already been enqueued, so a
	// notification can never delay or displace the call. Caller holds _mutex.
	void notifyEmergency(const pbx::EmergencyDial& emergency,
		const std::string& fromExt, const std::string& dialed, bool routed);

	void routeEmergencyCall(std::shared_ptr<SipMessage> data,
		const std::shared_ptr<SipClient>& caller,
		const pbx::EmergencyDial& emergency, const std::string& dialed);

	// `placedOut` (optional, Issue #166): true only when a call was actually
	// dispatched. The bool RETURN means "took ownership of the INVITE" and is
	// true for every refuse() path too, so a caller that must report what really
	// happened -- the emergency notification does -- has to ask for this.
	//
	// `codecRejectedOut` (optional, Issue #314): when non-null, the codec-offer
	// gate does NOT answer 488 itself on rejection -- it sets *codecRejectedOut
	// and returns false with nothing sent, so the caller can substitute its own
	// response. routeEmergencyCall() needs this: its purpose-built 503 (Issue
	// #166) would otherwise race the generic 488 this gate already sent, giving
	// one INVITE two final responses. Every other caller passes nullptr and gets
	// the original behaviour unchanged.
	bool originateAnchorCall(std::shared_ptr<SipMessage> data,
		const std::shared_ptr<SipClient>& caller, const std::string& destination,
		bool respondIfDisconnected, bool* placedOut = nullptr,
		bool* codecRejectedOut = nullptr);

	// First anchor media bridge with no active call, or nullptr if every slot is
	// busy (onAnchorInvite() then answers 503 Service Unavailable, mirroring the
	// 440/888 busy-refusal shape with a different status for the different meaning
	// — see that call site's comment). Caller holds _mutex.
	MediaBridge* acquireFreeAnchorBridge();

	// The active bridge serving `participantId` ("" never matches), or nullptr if
	// none is. Used by the CallEvent callback / tick()'s orphan sweep to find the
	// bridge for an upstream event that carries a participant id rather than a
	// Call-ID. Caller holds _mutex.
	MediaBridge* bridgeForParticipant(const std::string& participantId);

	// True iff every POCKETDIAL_MAX_ANCHOR_CALLS bridge slot is active — the
	// capacity gate for both a fresh 555 dial (onAnchorInvite) and a fresh
	// inbound anchor call (routeInboundAnchorCall). Caller holds _mutex.
	bool allBridgesBusy() const;

	// How many anchored calls may run at once: min(what the plugged-in provider
	// can drive, what the arrays are sized for). See the implementation comment —
	// the two are genuinely different limits, and a provider that hands back a
	// constant participant id (the loopback mock) cannot be run concurrently at
	// all without silently starving one leg's audio. Caller holds _mutex.
	unsigned anchorCallLimit() const;

	// Anchored calls currently up. Caller holds _mutex.
	unsigned activeAnchorCalls() const;

	// True iff the currently-selected anchor provider is Loopback — the boundary
	// between the two calling conventions this port has to support:
	//   * Loopback: makeCall()/dropCall()/answerCall() are cheap, bounded
	//     (~40 ms) thread-joins, so onAnchorInvite()/endCall() call them
	//     SYNCHRONOUSLY while holding _mutex (unchanged since Stage A) and
	//     setEventCallback() is left unwired — see the constructor's comment
	//     for why wiring it here specifically would deadlock (reapSimThreads()'s
	//     join, inside a synchronous makeCall()/dropCall(), racing the very
	//     callback this mutex-holding thread is blocked waiting to run).
	//   * any real anchor (TelephonyAnchorClient today): those calls are
	//     blocking TLS HTTP round trips, so every call site MUST go through
	//     asyncMakeCall()/asyncDropCall()/asyncAnswerCall() instead, and the
	//     CallEvent callback IS wired (that is how such a call ever completes).
	// A consequence, documented rather than silently accepted: LoopbackAnchorClient's
	// own simulateInboundCall()/CallEvent::Incoming test hook (see AnchorClient_test.cpp)
	// is therefore never exercised THROUGH RequestsHandler — only a real anchor
	// reaches routeInboundAnchorCall() in this port. Loopback's own contract is
	// still fully tested in isolation there.
	bool anchorIsSynchronous() const;

	// ── Anchor async wrappers (Stage B of the TelephonyAnchorClient port) ────────
	// makeCall()/dropCall()/answerCall() on a real anchor are blocking TLS HTTP
	// round trips — calling them under _mutex would stall the whole SIP thread for
	// the length of that HTTP call (this codebase's "no blocking I/O under the
	// registrar lock" invariant). Each wrapper spawns a PSRAM-stack worker task
	// (ESP: xTaskCreateWithCaps, 12288 bytes — 4096 bootlooped on real hardware,
	// the TLS handshake needs the headroom) or a host worker thread (via
	// spawnAnchorWorker(), reaped in tick()/the destructor) that calls the real
	// method off the SIP thread, then re-takes _mutex only to log/react. Never
	// called for a synchronous (Loopback) anchor — see anchorIsSynchronous().
	void asyncMakeCall(const std::string& destination, const std::string& callId, const std::string& callerNumber);
	// 503 a still-ringing outbound anchor call off its stored INVITE (endCall()
	// sends no response itself). Caller holds _mutex; outbox is _outbox on the
	// SIP thread or _asyncOutbox from a worker.
	void refuseRingingAnchor(const std::string& callId,
		std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>>& outbox);
	void asyncDropCall(const std::string& participantId);
	void asyncAnswerCall(const std::string& participantId);

	// Bind an outbound call's own leg (from asyncMakeCall's successful makeCall())
	// to its session, so the CallEvent::Answered/Dropped callback can match this
	// call even with several outbound anchor calls in flight. Takes _mutex itself
	// (called from the async worker, off the SIP thread, never while _mutex is
	// already held).
	void bindOutboundParticipant(const std::string& callId, const std::string& ownLeg);

#if !defined(ESP_PLATFORM) && !defined(ESP32)
	// Host-only worker-thread pool backing the async wrappers above (mirrors
	// drawbridge's own spawnAnchorWorker/reapAnchorWorkers exactly — ESP has no
	// equivalent because xTaskCreateWithCaps tasks self-delete). A detached
	// std::thread here would capture `this` and could outlive the handler in the
	// unit-test process (the exact hazard _anchorStartThread above already guards
	// against for the one-time start() call) — these run per CALL instead of once,
	// so they need their own pool, joined opportunistically here and drained in
	// ~RequestsHandler().
	struct AnchorWorker
	{
		std::thread thread;
		std::shared_ptr<std::atomic<bool>> done;
	};
	void spawnAnchorWorker(std::function<void()> job);
	// Join + erase every worker whose done-flag is set. Caller MUST hold
	// _anchorWorkMutex.
	void reapFinishedLocked();
	// Called from tick(): reap finished anchor workers. drainAll blocks until
	// every worker has finished (the destructor's belt-and-suspenders join).
	void reapAnchorWorkers(bool drainAll = false);
	std::mutex _anchorWorkMutex;
	std::vector<AnchorWorker> _anchorWorkThreads;
#endif

	// ── Inbound anchor call dispatch (Stage B) ────────────────────────────────────
	// An Incoming CallEvent means an external system is delivering a call to the
	// monitored route DN (_anchorRouteDn, cached at boot from the active
	// TelephonyApiConfig slot — see the constructor). That DN is a trunk route
	// point, not a phone, so the default is RING-ALL: fork an offerless INVITE to
	// every registered extension, first answer wins. Track A's DID -> extension
	// table (DidMapping) narrows this to a single target when the operator has
	// mapped this exact DN — see the DID-hook comment inside the definition.
	// Runs under _mutex (the CallEvent callback holds it).
	void routeInboundAnchorCall(const std::string& participantId, const std::string& callerId);

	// One delayed-offer INVITE fork toward `target` for the ring-all above, reusing
	// the session's shared Call-ID / Via branch / From-tag. Enqueues to
	// _asyncOutbox (this runs off the SIP receive thread).
	void buildInboundInviteFork(const std::shared_ptr<Session>& session,
		const std::shared_ptr<SipClient>& target, const std::string& callerDisplay);

	// CANCEL matching the forked INVITE transaction at `target` (same top Via
	// branch, From+tag, Call-ID, CSeq number). buildInboundCancel() is the
	// back-compat single-leg wrapper (CANCELs the session's current dest).
	std::shared_ptr<SipMessage> buildInboundCancelTo(const std::shared_ptr<Session>& session,
		const std::shared_ptr<SipClient>& target);
	std::shared_ptr<SipMessage> buildInboundCancel(const std::shared_ptr<Session>& session);

	// RFC 3261 §17.1.1.3: ACK a non-2xx final (486/480/487) within a forked
	// inbound-anchor INVITE transaction — there is no caller to relay it to, so
	// the server (UAC for this leg) must complete its own transaction.
	void ackInboundFinal(const std::shared_ptr<Session>& session, const std::shared_ptr<SipMessage>& data);

	// The handset's 200 OK to one of routeInboundAnchorCall()'s forked INVITEs:
	// learn its tag + RTP, bring up the media bridge, ACK with our SDP answer
	// (delayed-offer model), answer the upstream leg, and CANCEL the losing forks.
	// Called from onOk() before the generic session-answer path (isAnchorInbound()
	// sessions are server-as-UAC, which that generic path assumes the opposite of).
	void onInboundAnchorOk(const std::shared_ptr<SipMessage>& ok, const std::shared_ptr<Session>& session);

	void unregisterClient(std::string_view number);

	// Registration-lease handling (RFC 3261 §10.2.1)
	int parseRequestedExpires(const std::shared_ptr<SipMessage>& data) const;
	void sweepExpired();   // evict expired bindings; caller must hold _mutex
	void maybeSweep();     // throttled sweep; caller must hold _mutex

	std::optional<std::shared_ptr<SipClient>> findClient(std::string_view number);
	std::optional<std::shared_ptr<SipClient>> findClientByAddress(const sockaddr_in& addr);

	// Issue #202: the service-extension half of findRegistered(). Resolves a name
	// from the fixed ServiceExtensions.hpp table to its pre-allocated loopback peer
	// (address = this server's own), or nullptr when the name is not a service or
	// is a service marked NOT dialable. Deliberately NOT reachable from findClient:
	// findClient answers "is a phone REGISTERed under this number", and a service
	// must never be mistaken for one — the register-beep response path depends on
	// findClient("pbx") missing. Caller must hold _mutex.
	std::shared_ptr<SipClient> findServicePeer(std::string_view number);
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
	// per-leg RTP tasks. Both _loopbackClient and _telephonyAnchorClient are
	// REAL AnchorClient implementations (see TelephonyProvider.hpp);
	// _anchorClient points at whatever the boot-time provider registry
	// selected (see the constructor) so every call site below goes through
	// one pointer instead of the concrete type, the same indirection
	// TelephonyProviderRegistry exists to provide.
	//
	// TelephonyProviderType::Telephony is registered to _telephonyAnchorClient
	// (TelephonyAnchorClient, ported from drawbridge) — StubTelephonyProvider
	// is no longer instantiated here (the class itself stays in
	// TelephonyProvider.hpp as scaffolding for any future
	// genuinely-unimplemented provider type). telephonyProviderImplemented()
	// reports true for Telephony; boot selection (see the constructor) still
	// falls back to Loopback whenever no TelephonyApiConfig slot names
	// Telephony as active+enabled.
	//
	// Declaration order matters here: _mediaBridges MUST come after
	// _anchorRtpReceivers/_anchorRtpSenders/_loopbackClient/_telephonyAnchorClient/
	// _anchorClient so it is destroyed FIRST (C++ destroys members in REVERSE
	// declaration order) — ~MediaBridge() calls stopBridge(), which dereferences
	// _receiver/_sender/_anchor, and those must still be alive when that runs.
	RtpReceiver _anchorRtpReceivers[POCKETDIAL_MAX_ANCHOR_CALLS];
	RtpSender   _anchorRtpSenders[POCKETDIAL_MAX_ANCHOR_CALLS];
	LoopbackAnchorClient _loopbackClient;
	TelephonyAnchorClient _telephonyAnchorClient;
	TelephonyProviderRegistry _providerRegistry;
	AnchorClient* _anchorClient = nullptr;
	MediaBridge _mediaBridges[POCKETDIAL_MAX_ANCHOR_CALLS];

	// ── Voicemail (Issue #246, Stage 3 of #194) ──────────────────────────────────
	// POCKETDIAL_MAX_VOICEMAIL_LEGS concurrent deposit/retrieval legs, each
	// owning its own RTP receiver/sender pair -- same parallel-array,
	// index-matched shape as the anchor bridge pool above, but VoicemailLeg
	// holds no pointer back to its pair (callbacks are index-capturing
	// lambdas, wired at answer time in answerVoicemailDeposit()), so unlike
	// _mediaBridges there is no cross-member destruction-order constraint.
	RtpReceiver  _vmRtpReceivers[POCKETDIAL_MAX_VOICEMAIL_LEGS];
	RtpSender    _vmRtpSenders[POCKETDIAL_MAX_VOICEMAIL_LEGS];
	VoicemailLeg _vmLegs[POCKETDIAL_MAX_VOICEMAIL_LEGS];

	// ── Generic ITSP SIP trunk (Issue #164) ──────────────────────────────────
	//
	// A trunk call is a B2BUA with a relay in the middle: the handset's dialog
	// on one side, SipTrunk's dialog to the carrier on the other, and a PAIR of
	// RtpReceivers cross-wired so each one's raw sink feeds the other's
	// sendRaw().
	//
	// Two receivers and NO RtpSender, which is the part worth explaining. A
	// relay must put the carrier's packets back on the wire byte for byte:
	// RFC 4733 telephone-event and comfort noise have no representation in
	// RtpSender's pull-based FrameProvider, which fills PCMU frames stamped
	// with its own sequence and timestamp, so routing a relay through it would
	// silently convert every DTMF digit into noise. RtpReceiver::sendRaw()
	// transmits from the receiver's OWN bound socket instead, which also gives
	// symmetric RTP for free -- media leaves the exact port the SDP advertised,
	// which NAT-latching carriers require.
	//
	// Index-matched pair, same shape as the anchor and voicemail pools:
	//   _trunkRx[i]   faces the CARRIER   -- its port goes in the trunk INVITE
	//   _handsetRx[i] faces the HANDSET   -- its port goes in the 200 OK
	// A slot is free when neither is active. The owning Session remembers the
	// index (setTrunkRelaySlot), because a receiver carries no Call-ID.
	TrunkResolver _trunkResolver;
	SipTrunk      _sipTrunk{*this};
	RtpReceiver   _trunkRx[POCKETDIAL_MAX_TRUNK_CALLS];
	RtpReceiver   _handsetRx[POCKETDIAL_MAX_TRUNK_CALLS];

	// Recording/staging buffer pool (see PoolConfig.hpp's
	// POCKETDIAL_VOICEMAIL_MAX_MESSAGE_BYTES budget comment and
	// VoicemailArchive.hpp's class comment for why there are two arrays, not
	// one). Allocated once in the constructor, freed once in the destructor
	// -- never touched by any other code path. A null entry means boot-time
	// allocation failed for that leg; answerVoicemailDeposit() must check.
	uint8_t* _vmRecordBufs[POCKETDIAL_MAX_VOICEMAIL_LEGS] = {};
	uint8_t* _vmStagingBufs[POCKETDIAL_MAX_VOICEMAIL_LEGS] = {};

	// The SD-flush queue (VoicemailArchive.hpp) -- capacity matches the leg
	// count, since at most one finished recording per leg can be pending
	// flush at a time. Monotonic counter for the filename fallback when the
	// wall clock hasn't synced yet (see VoicemailArchive.hpp's
	// QueuedRecording::sequence doc comment).
	vmarchive::WriterQueue _vmFlushQueue{POCKETDIAL_MAX_VOICEMAIL_LEGS};
	uint64_t _vmFlushSequence = 0;

	// Found in review (Fable-Low, during the retrieval slice's design pass):
	// the comment above describes "at most one pending flush per leg" as an
	// invariant, but nothing enforced it. enqueueVoicemailFlush() copies a
	// finished recording into _vmStagingBufs[slot] and pushes a job for the
	// writer task, but releaseVoicemailLeg() (called right after, in
	// endCall()) frees the slot immediately -- _vmRtpReceivers[slot] goes
	// inactive before the writer task has necessarily even started reading
	// _vmStagingBufs[slot], let alone finished. A new deposit landing on
	// that same slot before the drain completes would memcpy its OWN
	// recording into the SAME staging buffer the writer is still mid-fwrite
	// from, corrupting or torn-mixing the FIRST message's file on SD --
	// silently, no error anywhere. This flag closes that: true from the
	// moment a flush job is actually queued for a slot until
	// vmarchive::drainAll()'s afterWrite callback confirms sink.write() has
	// returned for it (see drainVoicemailFlush() below) -- i.e. exactly the
	// window findFreeVoicemailSlot() must refuse to reuse the slot in.
	std::atomic<bool> _vmFlushBusy[POCKETDIAL_MAX_VOICEMAIL_LEGS]{};

	// ── Retrieval SD-I/O job machine (Issue #246, retrieval slice 3/3) ──────
	// listMessages()/readMessage()/markDeleted() are all SD I/O and must
	// never run on the SIP thread (same discipline as the flush pipeline
	// above). ONE job struct per slot, not a queue (advisor + Fable-Low
	// design review): a queue would let a second digit-driven request land
	// while the first is still in flight, and two jobs writing the same
	// slot's buffers concurrently is exactly the class of bug
	// _vmFlushBusy above exists to prevent on the deposit side. A single
	// digit-driven event (e.g. '7': delete the current message AND fetch
	// the next one's bytes) fills BOTH fields of the SAME job.
	//
	// State machine: SIP thread fills _vmSdJob[slot] then
	// _vmSdJobState[slot].store(Pending, release). The SD-I/O task (the
	// same writer task the flush pipeline already spawns) polls for
	// Pending, runs delete-then-list-then-read as flagged, writes results
	// into _vmMessageLists/_vmMessageCounts/_vmRecordBufs+_vmReadLength,
	// then store(Done, release). sweepVoicemailLegs() consumes a Done
	// result under acquire ordering, which the C++ memory model guarantees
	// makes everything the SD task wrote beforehand visible -- the same
	// producer/consumer handoff CdrArchive's queue already relies on, just
	// with a result to read back instead of fire-and-forget.
	enum class VmSdJobState : uint8_t { Idle, Pending, Done };
	struct VmSdJob
	{
		bool listRequested = false;
		char readName[48] = {};
		char deleteName[48] = {};
		char extension[32] = {};
		// Tag this job with the call it belongs to (Fable-Low review, Break
		// 2): a caller hanging up mid-job does NOT reset job state --
		// releaseVoicemailLeg() must not touch it, since the SD task owns
		// that transition -- so sweepVoicemailLegs() must verify a Done
		// result still belongs to the session consuming it before acting
		// on it, never assume the slot's current occupant issued it. Belt-
		// and-suspenders: findFreeVoicemailSlot() already refuses a slot
		// while a job is outstanding, so this should be unreachable in
		// practice -- the tag makes it impossible rather than merely
		// unreached.
		char callId[128] = {};
	};
	VmSdJob _vmSdJob[POCKETDIAL_MAX_VOICEMAIL_LEGS];
	std::atomic<VmSdJobState> _vmSdJobState[POCKETDIAL_MAX_VOICEMAIL_LEGS]{};

	// This slot's fetched mailbox listing, valid once a List job for it has
	// gone Done. Fixed-size (POCKETDIAL_VOICEMAIL_MAX_MESSAGES_PER_BOX per
	// slot, see PoolConfig.hpp) -- no heap, matching every other array in
	// this pool. ~3.8 KiB per slot (mostly MessageInfo::callId, which the
	// menu never reads) -- internal RAM, not PSRAM: small, fixed at boot,
	// no different in kind from _vmLegs/_vmRtpReceivers above.
	vmarchive::MessageInfo _vmMessageLists[POCKETDIAL_MAX_VOICEMAIL_LEGS]
		[POCKETDIAL_VOICEMAIL_MAX_MESSAGES_PER_BOX];
	size_t _vmMessageCounts[POCKETDIAL_MAX_VOICEMAIL_LEGS] = {};
	// How many bytes a completed Read job actually wrote into
	// _vmRecordBufs[slot] (REUSED here -- unused on a Retrieval leg, since
	// startRecording() is never called on one, and already sized to
	// POCKETDIAL_VOICEMAIL_MAX_MESSAGE_BYTES; zero new PSRAM).
	size_t _vmReadLength[POCKETDIAL_MAX_VOICEMAIL_LEGS] = {};

	// One pending digit per slot, written from the RTP task's DtmfSink
	// callback (must not block or take _mutex -- same contract
	// MediaBridge::DigitSink documents) and consumed by sweepVoicemailLegs()
	// on the SIP thread. Deliberately "deaf during I/O", not "newest wins"
	// (Fable-Low review): the DtmfSink only stores a digit when
	// _vmSdJobState[slot] == Idle, so a digit pressed while a job is
	// Pending is dropped outright -- the caller must press again once the
	// next message actually starts playing. Simpler and more honest than
	// remembering exactly one digit whose identity depends on arrival
	// timing relative to the job.
	std::atomic<char> _vmPendingDigit[POCKETDIAL_MAX_VOICEMAIL_LEGS]{};

	// Issue #284: RtpReceiver::DtmfSink is a raw function pointer + void* ctx,
	// not a std::function, so the retrieval leg's digit sink cannot capture
	// `this` and `slot` in a closure -- ctx points at one of these instead,
	// populated once per answer in answerVoicemailRetrieval() (the two member
	// arrays above never move, so the pointers stay valid for the leg's whole
	// life).
	struct VmDtmfCtx
	{
		std::atomic<VmSdJobState>* jobState = nullptr;
		std::atomic<char>*         pendingDigit = nullptr;
	};
	VmDtmfCtx _vmDtmfCtx[POCKETDIAL_MAX_VOICEMAIL_LEGS];

	// The RtpReceiver::DtmfSink trampoline itself -- see VmDtmfCtx above.
	// "Deaf during I/O", not "newest wins" (Fable-Low review): only stores a
	// digit while no SD job is in flight for this slot.
	static void vmDtmfSinkTrampoline(void* ctx, char digit, uint16_t durationMs);

	// The pure per-slot menu state machine (VoicemailMenu.hpp) driving a
	// Retrieval leg. A Deposit leg never touches this.
	VoicemailMenu _vmMenus[POCKETDIAL_MAX_VOICEMAIL_LEGS];

	// System deposit greeting: loaded once at boot from a fixed SD path,
	// PSRAM-resident, same "why the SD card stays off the media path" and
	// "why this one-shot allocation is allowed" reasoning as
	// HoldMusic::loadClip() -- this reuses HoldMusic::parseUlawWav() (the
	// pure parser) rather than HoldMusic itself, since HoldMusic is a
	// looping one-global-cursor fan-out engine and this needs neither. Null
	// (and _vmGreetingClipLen 0) when no greeting file is present -- graceful
	// degradation to "record immediately, no greeting", matching HoldMusic's
	// own "falls back to silence" philosophy rather than failing the call.
	// Per-extension custom greetings are a later slice.
	uint8_t* _vmGreetingClip = nullptr;
	size_t _vmGreetingClipLen = 0;
	// False when _vmGreetingClip points at memory this instance doesn't own
	// (setVoicemailGreetingForTest()'s caller-supplied buffer) -- the
	// destructor must never free() a test's stack/static array. True is the
	// correct default: the constructor's own loadVoicemailGreeting() call is
	// the only OTHER writer, and that path always heap-allocates.
	bool _vmGreetingClipOwned = true;
	void loadVoicemailGreeting();

	// The boot-selected provider TYPE (cached alongside _anchorClient itself —
	// see the constructor) and the monitored route DN an ACTIVE+ENABLED
	// TelephonyApiConfig slot supplied (pocket-dial's substitute for drawbridge's
	// TrunkConfig::sourceDn — see TelephonyApiConfig::Slot::routeDn). "" when no
	// such slot is active (Loopback boot, or an unimplemented/disabled slot).
	// anchorIsSynchronous() reads _anchorBootType; routeInboundAnchorCall() reads
	// _anchorRouteDn as the RING-ALL gate and the DID-mapping lookup key.
	TelephonyProviderType _anchorBootType = TelephonyProviderType::Loopback;
	std::string _anchorRouteDn;

	// Stage B of the TelephonyAnchorClient port: sends that originate OFF the SIP
	// receive thread (the CallEvent callback, which runs on the anchor's own WS
	// event task/thread) cannot append to _outbox — handle()/tick() clear it at
	// the start of every pass, and appending from another thread with no lock
	// would race that clear/scan. They land here instead; drainOutbox() (the
	// single chokepoint every deferred send already passes through) merges this
	// in before its own scan, so an async send gets the same retransmit tracking
	// and /api/pcap capture as any other. Guarded by _mutex, same as _outbox —
	// every writer (the CallEvent callback, buildInboundInviteFork/
	// buildInboundCancelTo's async callers) already holds it.
	std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>> _asyncOutbox;

#if !defined(ESP_PLATFORM) && !defined(ESP32)
	// Async anchor-start worker (host builds only; ESP spawns a FreeRTOS task
	// instead — see the constructor). Must be JOINED in ~RequestsHandler: a
	// detached thread here would capture `this` and could outlive the handler
	// in the unit-test process, segfaulting nondeterministically (mirrors
	// drawbridge's _anchorStartThread exactly).
	std::thread _anchorStartThread;
#endif

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

	// The inbound message currently being handled, or nullptr outside a handle()
	// pass (tick() drains with this unset). Used by drainOutbox() for exactly one
	// question: is an outbound entry the very object we just received?
	//
	// Several relay paths forward a message by pushing the SAME shared_ptr rather
	// than a clone — onReinvite's hold/resume relay (RequestsHandler.cpp:6787),
	// onUpdate's SDP relay (:6876), and the provisional relays that endHandle()
	// `data` straight through. Those are pure pass-through: the PBX is not the
	// sender, it is the wire. The originating phone owns retransmitting its own
	// re-INVITE under its own transaction (same branch, RFC 3261 §17.1.1), and it
	// keeps doing so until the far end's answer comes back through here — so a
	// PBX-side timer on top would put a second copy of the same branch on the
	// wire for every loss. That is the same double-send the authored-vs-relayed
	// rule prevents on the response side, and pointer identity is the exact test
	// for it: a message the PBX built is never the object it received.
	//
	// Raw pointer, not a shared_ptr: it is only ever compared, never dereferenced,
	// and the shared_ptr in `request` outlives the whole pass.
	const SipMessage* _passThroughMsg = nullptr;

	// ── RFC 4733 DTMF hand-off ring ─────────────────────────────────────────────
	// Producer: any RTP receive task (one per conference leg / anchor bridge).
	// Consumer: the SIP thread, via drainDtmfInbox() from handle() and tick().
	//
	// Guarded by its OWN mutex, deliberately NOT _mutex. This is the one place the
	// codebase's "everything under the big lock" convention is wrong: the producer
	// is a real-time media task, and making it wait on the engine lock would turn
	// every slow SIP pass into an audio glitch. The ring holds plain bytes — no
	// shared_ptr, no std::string, nothing that allocates or needs the engine's
	// object pools — so the critical section is a memcpy and the producer never
	// blocks for longer than another producer's memcpy.
	struct DtmfPress
	{
		char     callId[128]{};   // dialog the press belongs to
		char     digit = 0;
		uint8_t  source = 0;      // DtmfFeatureCodes::DigitSource
		uint32_t arrivedTick = 0; // DtmfFeatureCodes::nowTickMs() at capture
	};
	std::array<DtmfPress, POCKETDIAL_DTMF_INBOX> _dtmfInbox{};
	size_t                _dtmfInboxCount = 0;
	mutable std::mutex    _dtmfInboxMutex;
	std::atomic<uint64_t> _dtmfDropped{0};

	// Move everything the media tasks captured into the feature-code machine.
	// Caller holds _mutex; this takes _dtmfInboxMutex briefly to lift the batch
	// out, then releases it before dispatching, so a producer is never blocked
	// for the length of a feature-code action.
	void drainDtmfInbox();

	std::string _serverIp;
	std::string _localIp;   // resolved once at construction; avoids getPrimaryLocalIP() under _mutex
	int         _serverPort;

	std::atomic<uint64_t> _packetsProcessed{0};
	std::atomic<uint64_t> _packetsDropped{0};
	std::atomic<uint64_t> _sdpRejected{0};    // T-7 SDP admission refusals
	// Requests answered from a §17.2 server transaction's stored response rather
	// than re-run through the TU. A healthy LAN should sit near zero; a climbing
	// count is the packet-loss signal this layer exists to absorb, so it is worth
	// having on the dashboard next to packetsDropped rather than only in the log.
	std::atomic<uint64_t> _packetsAbsorbed{0};

	struct RegistrarSnapshot
	{
		std::vector<std::pair<std::string, std::string>> clients;
		std::vector<std::tuple<std::string, std::string, std::string, int>> sessions;
		std::vector<CallDetailRecord> cdr;   // newest first
		std::vector<std::string> dnd;        // extensions currently in DND
		std::vector<std::string> voicemail;  // extensions with voicemail enabled (Issue #246)
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
		std::vector<std::tuple<std::string, std::string, std::string, int>> dialRules;
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

	// The bounded Telephony-API credential slot table (ported from drawbridge)
	// and the DID -> extension inbound routing table (new). Both are
	// self-contained data models with their own NVS-namespace/host-file
	// persistence (see TelephonyApiConfig.hpp / DidMapping.hpp) and, unlike
	// _cfg above, need no OnChanged callback: neither has a dashboard-snapshot
	// mirror to keep in sync, because neither is read from the SIP hot path
	// yet (see each header's class/BOUNDARY comment). Loaded once at
	// construction (see the constructor); mutated only through
	// setTelephonyConfigSlot()/setTelephonyConfigActiveSlot()/
	// clearTelephonyConfigSlot()/clearAllTelephonyConfig()/setDidMapping()/
	// removeDidMapping()/clearAllDidMappings() above, all of which take
	// _mutex first.
	TelephonyApiConfig _tapiConfig;
	DidMapping _didMapping;
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
	// Service-extension peers (Issue #202), one slot per kServiceEndpoints entry and
	// addressed by the SAME index. Built once in the constructor and never resized,
	// so findServicePeer() hands back a long-lived object without touching the heap
	// in the packet path — the pools above are recycled by use_count(), these are
	// not, because a service identity is permanent rather than per-call.
	//
	// A separate array, NOT reserved slots inside _clientPool: registration capacity
	// belongs to handsets, and keeping the storage apart is what makes "never in the
	// roster / never adoptable in Learn mode" true by construction rather than by a
	// filter somebody must remember to apply at each read site.
	std::array<std::shared_ptr<SipClient>, POCKETDIAL_MAX_SERVICES> _servicePeers{};

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
	// _cdr (the *69 last-caller lookup) by reference. Guarded by this engine's
	// _mutex, same "single-threaded SIP handler path" contract the original
	// onDtmfInfo() documented.
	DtmfFeatureCodes _dtmf{*this, _cfg, _cdr};

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
