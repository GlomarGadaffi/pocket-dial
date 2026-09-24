// RequestsHandler.cpp: Issues #24 and #28 resolved.
#include "RequestsHandler.hpp"
#include "SipMessagePool.hpp"
#include <atomic>
#include <iostream>
#include <sstream>
#include <cctype>
#include <cstring>
#include <cstdlib>
#include <algorithm>
#include "SipMessageTypes.h"
#include "SipSdpMessage.hpp"
#include "IDGen.hpp"
#include "IPHelper.hpp"
#include "PoolConfig.hpp"
#include "CallDetailRecord.hpp"
#include "CdrArchive.hpp"  // Issue #194 Stage 1: SD CDR archive (endCall() hook)
#include "TimeSync.hpp"    // Issue #246: voicemail flush timestamp (endCall() hook)
#include "PbxConfig.hpp"
#include "EmergencyCall.hpp"  // Issue #166: 911/933 classification, ahead of the dial plan
#include "PbxPersist.hpp"
#include "SipHeaderUtil.hpp"
#include "SipWireUtil.hpp"
#include "AdminAuth.hpp"
#include "SipDigest.hpp"
#include "SipSecretStore.hpp"
#include "ArpLookup.hpp"
#include "PsramTask.hpp"   // PD_TASK_STACK_CAPS / xTaskCreateWithCaps / vTaskDeleteWithCaps (ESP-only)

// inet_pton for the service-extension loopback address (Issue #202). RequestsHandler.hpp
// already pulls in the platform socket header; on POSIX and Win32 the ADDRESS-CONVERSION
// declarations live in a second header, which is what these add. lwip/sockets.h carries
// them itself on the device.
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	// nothing further: lwip/sockets.h already declares inet_pton
#elif defined(__linux__) || defined(__APPLE__)
	#include <arpa/inet.h>
#elif defined _WIN32 || defined _WIN64
	#include <ws2tcpip.h>
#endif

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	// PBX config (call-forward / ring groups) and the persistent CDR ring live in
	// NVS on the device. nvs_flash/nvs are core ESP-IDF components present on every
	// transport, so they gate on ESP_PLATFORM (not POCKETDIAL_HAS_WIFI). On host the
	// in-memory maps/ring ARE the store and these calls compile out (see the
	// load*/persist* helpers at the bottom of this file).
	#include "nvs_flash.h"
	#include "nvs.h"
	#include "esp_sntp.h"
	#include "esp_system.h"
	#include "esp_idf_version.h"
#endif

// File-scope static helpers defined later in this translation unit.
static bool sameAddress(const sockaddr_in&, const sockaddr_in&);
static std::string stripHeaderName(std::string_view fullLine);

namespace
{
	// Default lease granted when a REGISTER does not request one (seconds).
	constexpr int DEFAULT_EXPIRES = 3600;
	// Upper bound we are willing to grant, regardless of what the client asks.
	constexpr int MAX_EXPIRES = 3600;
	// Minimum non-zero lease, to avoid pathologically short registrations.
	constexpr int MIN_EXPIRES = 30;
	// How often the opportunistic sweep is allowed to run.
	constexpr auto SWEEP_INTERVAL = std::chrono::seconds(1);

	// How long an unanswered leg rings before the no-answer action fires (CFNA
	// forward, or advancing to the next hunt-group member). Shared with
	// CallForker::huntRingNext, so it now lives at pbx::kNoAnswerTimeout
	// (PbxConfig.hpp) instead of file-local here.

	// NVS namespace for the persisted PBX config, pbxcfg
	// (DtmfFeatureCodes::load()/saveAdminExt()) is pbxpersist::kNvsNamespace
	// (PbxPersist.hpp) so there is exactly one definition of "pbxcfg" in the
	// codebase. The CDR ring's own namespace ("cdrlog") lives on CdrRing.cpp.

	// Virtual extension for the anchored-media bridge (opt-in,
	// docs/FEATURE_ROADMAP.md's "Anchored media" extension point). Dialing this
	// fixed code bridges the caller to whatever AnchorClient the boot-time
	// provider registry selected — Loopback by default, and the only
	// implementation this project ships. See RequestsHandler.hpp's
	// onAnchorInvite() comment for why a dedicated reserved virtual extension
	// (matching 777/440/888/999) was chosen over a trunk-access prefix or an
	// unregistered-number fallback.
	constexpr const char* kAnchorCallExt = "555";

	// Issue #246, retrieval slice 3/3: voicemail retrieval dial-in. Matches
	// pbx::isReservedExtension()'s own "796" literal -- see that function's
	// comment for why 700 (the originally-planned number) collided with the
	// park-orbit range instead.
	constexpr const char* kVoicemailRetrievalExt = "796";

	// Issue #194 audit: isValidAor() had a header comment (CallDetailRecord.hpp)
	// claiming it bounded caller/callee length. It never did -- charset only,
	// no size check -- which let an unbounded AOR heap-allocate inside every
	// CdrRing slot (and, now, every queued SD-archive line). A real SIP AOR
	// user-part is nowhere near this long; 64 is generous headroom over every
	// extension/feature-code/DID this codebase dials (longest today: 4-digit
	// park orbits/page zones, PIN-bearing DTMF admin codes under 16 chars) while
	// still refusing a pathological value outright rather than silently
	// truncating it somewhere downstream.
	constexpr size_t kMaxAorLen = 64;

	// How long a CONNECTED outbound anchor call waits for the handset's ACK before
	// tick() treats it as abandoned (handset gone, or its 200 OK arrived too late)
	// and reaps the upstream leg + bridge. Re-arms the ring timer that was set for
	// the no-answer window (pbx::kNoAnswerTimeout) at the moment the CallEvent
	// callback sends the 200 OK. Loopback never arms this (see onAck's kAnchorCallExt
	// branch): it answers synchronously and clears any timer immediately.
	constexpr auto ANCHOR_ACK_TIMEOUT = std::chrono::seconds(15);

	// How long an outbound anchor/trunk call may RING before tick() reaps it.
	//
	// Deliberately NOT pbx::kNoAnswerTimeout. That constant is documented as "how
	// long an unanswered leg rings before the no-answer action fires (CFNA forward,
	// or advancing to the next hunt-group member)" — an INTERNAL-extension number,
	// and one the operator can work around by simply not configuring CFNA (an
	// extension with no forward never arms a ring timer at all). The outbound
	// anchor path inherited it when the zombie-reaper landed, and nothing ever
	// argued 20 s was a correct PSTN window.
	//
	// It is not. A US mobile typically rings 25-30 s before its carrier voicemail
	// answers, and the clock here starts when the HANDSET's INVITE is accepted —
	// before the ~1 s makeCall TLS round trip and before the provider has even
	// begun dialling. Measured on hardware: a real call to a mobile was reaped at
	// ~19 s of a 20 s budget, a few seconds short of voicemail pickup, and the
	// caller got a 503 (issue #148's sibling; see the PR for the capture).
	//
	// This must still be FINITE and reasonably tight. It is the only backstop for
	// a leg the provider still lists but that never progresses: the anchor's own
	// reconcile watchdog tears down only legs that have VANISHED from the DN, so
	// a stuck-but-present leg would otherwise pin the single
	// POCKETDIAL_MAX_ANCHOR_CALLS slot forever. 60 s clears carrier voicemail with
	// margin while bounding that worst case; do not make it unbounded, and do not
	// re-arm it on provider progress events (the provider reports our own control
	// leg's state, which sits at "Dialing" right through far-end alerting — there
	// is no alerting signal to key off).
	constexpr auto ANCHOR_NO_ANSWER_TIMEOUT = std::chrono::seconds(60);
}

RequestsHandler::RequestsHandler(std::string serverIp, int serverPort,
	OnHandledEvent onHandledEvent) :
	_onHandled(onHandledEvent),
	_serverIp(std::move(serverIp)),
	_localIp(_serverIp == "0.0.0.0" ? getPrimaryLocalIP() : _serverIp),
	_serverPort(serverPort)
{
	initHandlers();

	// Attach music on hold to the park orbits (issue #162). Attached unconditionally
	// and unloaded: ParkOrbit checks isLoaded() per park, so a board with no clip
	// answers exactly as it always did (a=inactive, silent hold). Loading a clip is
	// a separate, later step — see startHoldMusic().
	_park.setHoldMusic(&_holdMusic);

	// Issue #164: SipTrunk reports dialog transitions through this. Registered
	// once here and never changed -- the listener is this object, which outlives
	// the trunk it is handed to.
	_sipTrunk.setListener(this);

	// Pre-allocate pools (Issue #53). Capacities are compile-time tunable via
	// PoolConfig.hpp (-DPOCKETDIAL_MAX_* overrides); defaults preserve 32/8/32.
	_clientPool.reserve(POCKETDIAL_MAX_CLIENTS);
	for (int i = 0; i < POCKETDIAL_MAX_CLIENTS; ++i)
	{
		_clientPool.push_back(std::make_shared<SipClient>());
	}
	_sessionPool.reserve(POCKETDIAL_MAX_SESSIONS);
	for (int i = 0; i < POCKETDIAL_MAX_SESSIONS; ++i)
	{
		_sessionPool.push_back(std::make_shared<Session>());
	}
	sipmsgpool::ensureInitialized();
	_virtualPeerPool.reserve(POCKETDIAL_VIRTUAL_PEERS);
	for (int i = 0; i < POCKETDIAL_VIRTUAL_PEERS; ++i)
	{
		_virtualPeerPool.push_back(std::make_shared<SipClient>());
	}

	// Service extensions (Issue #202): one permanent peer per seeded entry, bound
	// to THIS SERVER'S OWN address. That address is the whole idea — a call routed
	// to a service is meant to come back to us and be intercepted by name the way
	// 440/555/777/888 already are, rather than each routing path growing its own
	// special case. Built here, once, so findServicePeer() never allocates in the
	// packet path; _localIp is resolved in the member-init list above and is never
	// reassigned afterwards, so the address cannot go stale under us.
	//
	// The lease is nominal: these are not registrations. sweepExpired() walks
	// _clientPool only, so nothing ever ages one of these out — the long value is
	// there so a stray isExpired() check can never make a service look dead.
	{
		sockaddr_in self{};
		self.sin_family = AF_INET;
		self.sin_port   = htons(static_cast<uint16_t>(_serverPort));
		if (::inet_pton(AF_INET, _localIp.c_str(), &self.sin_addr) != 1)
		{
			// Unparseable local IP (should not happen: it is either the configured
			// literal or getPrimaryLocalIP()'s output). Fall back to loopback rather
			// than leaving the address zeroed, so a service peer never points at
			// 0.0.0.0 — every consumer treats the address as a real destination.
			self.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		}
		for (std::size_t i = 0; i < pbx::kServiceEndpointCount; ++i)
		{
			_servicePeers[i] = std::make_shared<SipClient>(
				std::string(pbx::kServiceEndpoints[i].name), self, /*expiresSeconds=*/0x7FFFFFFF);
		}
	}

	// Reload persisted PBX config (call-forward / ring groups) and the CDR ring from
	// NVS so they survive reboot. No-ops on host. Construction is single-threaded
	// (no handler is dispatching yet), so these run without holding _mutex.
	_cfg.loadPbxConfig();
	// Telephony-API credential slots + DID->extension mapping (new, Part 2):
	// same "reload once at construction, single-threaded, no lock needed" story
	// as _cfg.loadPbxConfig() just above.
	_tapiConfig.load();
	_didMapping.load();
	_cdr.load();
	// Task 2B: load the admin extension from NVS (defaults to "1001" if absent).
	_dtmf.load();
	// STAGE 2: load the registrar mode (defaults to the POCKETDIAL_OPEN_REGISTRAR
	// seed) and the adopted-device registry from NVS.
	_registrar.loadMode();
	_registrar.loadDevices();
	// Prewarm the per-extension HA1 cache off the REGISTER hot path so the first
	// Secure REGISTER does not pay a blocking NVS read while holding _mutex.
	SipSecretStore::warmCache();
	// Seed the dashboard snapshot with the loaded devices so the TUI sees adopted
	// devices immediately on boot (online flags start false until each re-REGISTERs).
	refreshDeviceSnapshot();

	// ── Anchored media (opt-in; docs/FEATURE_ROADMAP.md): wire the AnchorClient/
	// MediaBridge extension point into call routing. Both provider slots now
	// have a real implementation: LoopbackAnchorClient (on-box mock, the safe
	// default) and TelephonyAnchorClient (WAN-anchor client ported from
	// drawbridge — Stage A of that port; see TelephonyProvider.hpp's class
	// comment). Boot selection below reads the Telephony-API credential slot
	// table (also ported from drawbridge) so an operator-provisioned
	// ACTIVE+ENABLED slot can pick Telephony over the Loopback default;
	// telephonyProviderImplemented() remains the belt-and-braces guard against
	// any FUTURE enumerator that is declared but not yet backed by a
	// registered client.
	_providerRegistry.registerProvider(TelephonyProviderType::Loopback, &_loopbackClient);
	_providerRegistry.registerProvider(TelephonyProviderType::Telephony, &_telephonyAnchorClient);

	// Resolve the boot provider TYPE from the credential slot table. Default =
	// Loopback; an ACTIVE+ENABLED slot overrides it, falling back to Loopback
	// with an honest log if that slot names a provider that isn't (yet)
	// implemented. Construction is single-threaded (no handler is dispatching
	// yet), so this runs without holding _mutex — same as _tapiConfig.load()
	// a few lines above.
	TelephonyProviderType bootType = TelephonyProviderType::Loopback;
	std::string tapiUrl, tapiId, tapiSecret, tapiDn;
	bool credsFromSlot = false;
	{
		const size_t act = _tapiConfig.activeSlot();
		const TelephonyApiConfig::Slot* slot = _tapiConfig.bootSlot(act);
		if (slot != nullptr && slot->enabled)
		{
			if (telephonyProviderImplemented(slot->type))
			{
				bootType = slot->type;
				tapiUrl = slot->baseUrl; tapiId = slot->clientId;
				tapiSecret = slot->secret; tapiDn = slot->routeDn;
				credsFromSlot = (slot->type != TelephonyProviderType::Loopback);
			}
			else
			{
				queueLog(std::string("[Telephony] Active provider ") +
				         telephonyProviderName(slot->type) +
				         " is not implemented yet — falling back to loopback", true);
			}
		}
	}

	AnchorClient* selectedAnchor = _providerRegistry.select(bootType);
	_anchorClient = (selectedAnchor && telephonyProviderImplemented(bootType))
		? selectedAnchor : nullptr;
	if (_anchorClient == nullptr)
	{
		_anchorClient = &_loopbackClient;   // registry is total today; belt+braces
		bootType = TelephonyProviderType::Loopback;
	}

	// Cache the FINAL decision (after the belt-braces fallback above) — every call
	// site downstream (onAnchorInvite, endCall, the CallEvent callback,
	// routeInboundAnchorCall) reads these two members rather than re-deriving them.
	// _anchorRouteDn is pocket-dial's substitute for drawbridge's TrunkConfig::
	// sourceDn: the monitored route DN an ACTIVE+ENABLED Telephony slot supplies
	// (TelephonyApiConfig::Slot::routeDn) — "" whenever no such slot is active
	// (Loopback boot).
	_anchorBootType = bootType;
	_anchorRouteDn = tapiDn;

	if (_anchorClient)
	{
		if (credsFromSlot)
		{
			_anchorClient->init(tapiUrl, tapiId, tapiSecret, tapiDn);
		}
		else
		{
			_anchorClient->init("", "", "", "");   // Loopback needs no real credentials
		}
		// Drop the local plaintext copy now the client holds it (best-effort).
		std::fill(tapiSecret.begin(), tapiSecret.end(), '\0');

		// Push the re-warm cadence into the freshly-selected anchor (no-op on
		// Loopback — AnchorClient::setRewarmIntervalSec() defaults to a no-op
		// override); minutes -> seconds, mirroring drawbridge's own boot wiring.
		// _rewarmMinutes has no NVS load/dashboard setter in pocket-dial today (it
		// sits at its declared default, unlike drawbridge's TUI-exposed copy) —
		// wiring that persistence is a separate, later piece of work; this line
		// only makes the existing atomic actually reach the anchor once one exists.
		_anchorClient->setRewarmIntervalSec(
			static_cast<uint32_t>(_rewarmMinutes.load(std::memory_order_relaxed)) * 60u);

		// Wire each anchor media bridge to its own RTP receiver/sender pair, then
		// install ONE anchor rx callback fanning each call's inbound audio out to
		// the bridge owning that participant — MediaBridge_test.cpp's
		// AnchorAudioReachesPlayoutBufferThroughRxFanout proves this exact wiring
		// in isolation. One callback covers every bridge; the AnchorClient
		// interface exposes only a single rx slot.
		for (size_t i = 0; i < POCKETDIAL_MAX_ANCHOR_CALLS; ++i)
		{
			_mediaBridges[i].init(&_anchorRtpReceivers[i], &_anchorRtpSenders[i], _anchorClient);
			// Issue #218: same wiring as ParkOrbit::setHoldMusic() below, so a
			// held anchor/trunk call can tap the shared clip too.
			_mediaBridges[i].setHoldMusic(&_holdMusic);
			// Issue #199 item 3. On an anchored (555 / trunk) call the board IS
			// the far end of the handset's media, so RFC 4733 is the only way a
			// keypress reaches it short of SIP INFO — and this is the path #194's
			// voicemail and IVR stages will navigate menus over.
			_mediaBridges[i].setDigitSink([this](std::string_view legCallId, char digit) {
				queueDtmfDigit(legCallId, digit);
			});
		}
		_anchorClient->registerAudioRxCallback(
			[this](std::string_view participantId, const int16_t* samples, size_t count)
			{
				for (auto& b : _mediaBridges)
				{
					if (b.feedRx(participantId, samples, count)) break;
				}
			});

		// setEventCallback() is wired ONLY for a real (non-Loopback) anchor — Stage
		// B of the TelephonyAnchorClient port. Loopback stays exactly as before
		// (unwired): its makeCall()/dropCall()/answerCall() synchronously JOIN
		// their own simulation thread(s) (reapSimThreads()), and onAnchorInvite()/
		// endCall() call them while holding _mutex (anchorIsSynchronous() ==
		// true keeps that path byte-for-byte unchanged from before this stage) —
		// an event callback that itself took _mutex would deadlock its own
		// caller: the SIP thread would be blocked inside reapSimThreads()'s
		// join() waiting for a sim thread that is itself blocked trying to lock
		// the _mutex the SIP thread is already holding. A real anchor's
		// makeCall()/dropCall()/answerCall() are blocking TLS HTTP round trips
		// instead, so every call site for one goes through asyncMakeCall()/
		// asyncDropCall()/asyncAnswerCall() (spawned off the SIP thread) rather
		// than being called directly under _mutex — see anchorIsSynchronous()'s
		// doc comment, onAnchorInvite(), and endCall()'s anchor-bridge safety net.
		if (!anchorIsSynchronous())
		{
			_anchorClient->setEventCallback([this](const AnchorClient::CallEvent& ev) {
				std::lock_guard<std::mutex> lock(_mutex);
				if (ev.type == AnchorClient::CallEvent::Answered)
				{
					queueLog("[Telephony] Event: Answered, participantId=" + ev.participantId);
					// Bind THIS answered participant to ITS session. asyncMakeCall's
					// worker stamped the own leg onto the session at origination
					// (bindOutboundParticipant), so match by participant id; fall back
					// to a still-unbound Invited anchor session (covers a rare
					// Answered-before-bind race, same as drawbridge's #100 fix).
					std::shared_ptr<Session> session;
					std::string callId;
					for (auto& [cid, s] : _sessions)
					{
						if (s->isAnchor() && !s->isAnchorInbound() &&
						    s->getState() == Session::State::Invited &&
						    s->getAnchorParticipantId() == ev.participantId)
						{
							session = s; callId = cid; break;
						}
					}
					if (!session)
					{
						for (auto& [cid, s] : _sessions)
						{
							if (s->isAnchor() && !s->isAnchorInbound() &&
							    s->getState() == Session::State::Invited &&
							    s->getAnchorParticipantId().empty())
							{
								session = s; callId = cid; break;
							}
						}
					}
					if (session)
					{
						auto caller = session->getSrc();
						std::string handsetIp;
						uint16_t handsetPort = 0;
						auto inviteMsg = session->getInviteMessage();
						if (caller && inviteMsg && parseCallerRtp(inviteMsg, handsetIp, handsetPort))
						{
							const std::string activeIp = _localIp;
							// Reuse the To-tag from the 180 Ringing so the 200 OK lands in
							// the SAME dialog the phone is already ringing (a fresh tag
							// leaves Yealink-class phones stuck ringing).
							std::string toTag = session->getLocalTag();
							if (toTag.empty()) toTag = IDGen::GenerateID(9); // defensive fallback
							// Claim a free media bridge for this call, starting it FIRST so
							// the receiver's ephemeral RX port is known before the SDP
							// answer is built — that port is what the handset must send
							// its audio to.
							MediaBridge* bridge = bridgeForParticipant(ev.participantId);
							if (!bridge) bridge = acquireFreeAnchorBridge();
							if (bridge && bridge->startBridge(handsetIp, handsetPort, callId, ev.participantId))
							{
								const int rxPort = bridge->receiverPort();
								const std::string sdpBody = buildMediaSdp(activeIp, rxPort, /*sendrecv=*/true);
								auto ok = buildOkWithSdp(inviteMsg, activeIp, toTag, sdpBody);
								if (ok)
								{
									// Runs on the anchor's own WS event task, NOT the SIP
									// receive thread — use _asyncOutbox so the start-of-pass
									// _outbox.clear() in handle()/tick() can't wipe this 200 OK.
									_asyncOutbox.emplace_back(inviteMsg->getSource(), std::move(ok));
									session->setState(Session::State::Connected);
									session->setAnchorParticipantId(ev.participantId);
									// Issue #232: toTag above is already this leg's own tag (reused
									// from the 180 Ringing), but nothing had stored the dialog
									// headers themselves — getDialogFrom()/getDialogTo() stayed
									// empty, so forceDisconnect()'s #72 guard could never BYE this
									// handset. Same fix as the 777/888 answer sites.
									session->setDialogHeaders(std::string(inviteMsg->getFrom()),
										std::string(inviteMsg->getTo()) + ";tag=" + toTag);
									// Re-arm as an ACK deadline: if the handset never ACKs this
									// 200 (bridged late, past its own timeout, phone already
									// gave up), tick() reaps the call and drops the anchor leg +
									// bridge instead of zombie-ing it. onAck clears this on a
									// healthy call (~1 s).
									session->armRingTimer(std::chrono::steady_clock::now() + ANCHOR_ACK_TIMEOUT);
									queueLog("[Telephony] MediaBridge started: handset=" + handsetIp + ":" +
									         std::to_string(handsetPort) + " <-> anchor (rx port " +
									         std::to_string(rxPort) + ")");
								}
								else
								{
									bridge->stopBridge();
									queueLog("[Telephony] Answered: message pool exhausted, bridge unwound", true);
								}
							}
							else
							{
								queueLog("[Telephony] MediaBridge failed to start (no free bridge)", true);
							}
						}
					}
				}
				else if (ev.type == AnchorClient::CallEvent::Incoming)
				{
					queueLog("[Telephony] Event: Incoming, participantId=" + ev.participantId +
					         (ev.callerId.empty() ? "" : (", caller=" + ev.callerId)));
					routeInboundAnchorCall(ev.participantId, ev.callerId);
				}
				else if (ev.type == AnchorClient::CallEvent::Dropped)
				{
					queueLog("[Telephony] Event: Dropped, participantId=" + ev.participantId);
					// Terminate ONLY the session for THIS participant and stop just its
					// media bridge (drawbridge's #100 fix — never the first anchor
					// session found, which would tear down an unrelated concurrent call).
					for (auto& [callId, session] : _sessions)
					{
						if (!session->isAnchor()) continue;
						if (session->getAnchorParticipantId() != ev.participantId) continue;
						session->setAnchorLegReleased();   // 3CX already dropped it (#379)

						if (MediaBridge* b = bridgeForParticipant(ev.participantId)) b->stopBridge();
						const std::string activeIp = _localIp;
						std::string localTag = session->getLocalTag();
						if (localTag.empty()) localTag = IDGen::GenerateID(9); // defensive fallback

						if (session->isAnchorInbound())
						{
							// INBOUND: we are the UAC toward the handset (dest). If it
							// already ANSWERED (Connected, we hold its tag) -> BYE it; if
							// still RINGING -> CANCEL our outstanding fork INVITEs instead.
							// All sends use _asyncOutbox (this runs off the SIP thread).
							auto handset = session->getDest();
							if (handset && session->getState() == Session::State::Connected &&
							    !session->getRemoteTag().empty())
							{
								const std::string srcIpPort = activeIp + ":" + std::to_string(_serverPort);
								const std::string srcNum = session->getSrc() ? session->getSrc()->getNumber() : std::string("PSTN");
								const std::string fromHeader = "\"" + srcNum + "\" <sip:" + handset->getNumber() +
								                               "@" + srcIpPort + ">;tag=" + localTag;
								const std::string toHeader = "<sip:" + handset->getNumber() + "@" + activeIp +
								                             ">;tag=" + session->getRemoteTag();
								auto bye = buildServerBye(handset->getNumber(), handset->getAddress(), callId,
								                          fromHeader, toHeader);
								if (bye) _asyncOutbox.emplace_back(handset->getAddress(), std::move(bye));
							}
							else
							{
								for (const auto& target : session->getPendingTargets())
								{
									auto cancel = buildInboundCancelTo(session, target);
									if (cancel) _asyncOutbox.emplace_back(target->getAddress(), std::move(cancel));
								}
							}
							std::string localCallId = callId;
							endCall(localCallId, ev.participantId, handset ? handset->getNumber() : "",
							        "anchor hangup (inbound)");
							break;
						}

						// OUTBOUND: server is UAS; BYE the original caller (src). From
						// carries the To-tag minted on the 180/200 — tag-strict handsets
						// (Yealink) reject a BYE without it and stay off-hook on a dead call.
						auto caller = session->getSrc();
						auto inviteMsg = session->getInviteMessage();
						if (caller && inviteMsg)
						{
							const std::string fromHeader = "<sip:" + std::string(inviteMsg->getToNumber()) +
							                               "@" + activeIp + ">;tag=" + localTag;
							auto bye = buildServerBye(caller->getNumber(), caller->getAddress(), callId,
							                          fromHeader, std::string(inviteMsg->getFrom()));
							if (bye) _asyncOutbox.emplace_back(caller->getAddress(), std::move(bye));
						}

						std::string localCallId = callId;
						endCall(localCallId, session->getSrc() ? session->getSrc()->getNumber() : "",
						        inviteMsg ? inviteMsg->getToNumber() : "", "anchor hangup");
						break;
					}
				}
			});
		}

		// start() runs SYNCHRONOUSLY for Loopback (unchanged from before this
		// port — LoopbackAnchorClient::start() is a flag store, not I/O), but
		// MUST run off this constructor's call stack for any other provider:
		// TelephonyAnchorClient::start() does a full mbedTLS handshake
		// (fetchToken) + WS connect, and blocking construction on that would
		// stall boot. This branch (on bootType, not on platform) is a
		// deliberate departure from drawbridge's constructor, which always
		// spawns asynchronously regardless of provider: pocket-dial's own host
		// suite (AnchorRouting_test.cpp) constructs a RequestsHandler and
		// dials the 555 anchor extension on the very next line with no wait,
		// which needs LoopbackAnchorClient::isConnected() true the instant the
		// constructor returns — spawning even Loopback's start() onto a
		// background thread/task races that assertion. Every test today gets
		// bootType==Loopback (no active slot on a fresh _tapiConfig.load()),
		// so this preserves their exact timing while still fixing the real
		// hazard (blocking TLS in the constructor) for a real anchor.
		if (bootType == TelephonyProviderType::Loopback)
		{
			if (_anchorClient->start())
			{
				queueLog("[Anchor] LOOPBACK client started");
			}
			else
			{
				queueLog("[Anchor] failed to start anchor client", true);
			}
		}
		else
		{
			// Spawn off this constructor's call stack exactly like drawbridge's
			// constructor does — an ESP task with real stack headroom (12288:
			// 4096 bootlooped on real hardware, fetchToken's TLS handshake
			// needs the room), or a joined host thread (_anchorStartThread,
			// joined in ~RequestsHandler — a detached thread here would
			// capture `this` and could outlive the handler in the unit-test
			// process).
#if defined(ESP_PLATFORM) || defined(ESP32)
			struct StartClientArg { AnchorClient* anchor; RequestsHandler* handler; };
			auto* startArg = new StartClientArg{ _anchorClient, this };
			xTaskCreate([](void* p) {
				auto* sca = static_cast<StartClientArg*>(p);
				if (sca->anchor->start())
				{
					std::lock_guard<std::mutex> lock(sca->handler->_mutex);
					sca->handler->queueLog("[Anchor] client started");
				}
				else
				{
					std::lock_guard<std::mutex> lock(sca->handler->_mutex);
					sca->handler->queueLog("[Anchor] failed to start anchor client", true);
				}
				delete sca;
				vTaskDelete(NULL);
			}, "tel_start", 12288, startArg, 5, NULL);
#else
			_anchorStartThread = std::thread([this]() {
				if (_anchorClient->start())
				{
					std::lock_guard<std::mutex> lock(_mutex);
					queueLog("[Anchor] client started");
				}
				else
				{
					std::lock_guard<std::mutex> lock(_mutex);
					queueLog("[Anchor] failed to start anchor client", true);
				}
			});
#endif
		}
	}

	// Issue #246: the voicemail recording/staging buffer pool. Same
	// "deliberate, narrow exception to no-heap-after-init" reasoning
	// HoldMusic::loadClip() documents in full -- one-shot, bounded, off the
	// media path, runs on whatever thread constructs this object (never the
	// SIP/RTP tasks, since those don't exist until after construction). PSRAM
	// by preference, same fallback-to-internal-RAM order as HoldMusic. Two
	// buffers per leg, not one: the record buffer is what onCallerRtp() fills
	// live; the staging buffer is a separate copy the flush queue owns after
	// BYE, so releaseVoicemailLeg() can reset() the leg (and let it take a
	// new call) without waiting for the writer task to finish reading -- see
	// VoicemailArchive.hpp's class comment.
	for (size_t i = 0; i < POCKETDIAL_MAX_VOICEMAIL_LEGS; ++i)
	{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
		_vmRecordBufs[i] = static_cast<uint8_t*>(
			heap_caps_malloc(POCKETDIAL_VOICEMAIL_MAX_MESSAGE_BYTES, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
		if (_vmRecordBufs[i] == nullptr)
		{
			_vmRecordBufs[i] = static_cast<uint8_t*>(
				heap_caps_malloc(POCKETDIAL_VOICEMAIL_MAX_MESSAGE_BYTES, MALLOC_CAP_8BIT));
		}
		_vmStagingBufs[i] = static_cast<uint8_t*>(
			heap_caps_malloc(POCKETDIAL_VOICEMAIL_MAX_MESSAGE_BYTES, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
		if (_vmStagingBufs[i] == nullptr)
		{
			_vmStagingBufs[i] = static_cast<uint8_t*>(
				heap_caps_malloc(POCKETDIAL_VOICEMAIL_MAX_MESSAGE_BYTES, MALLOC_CAP_8BIT));
		}
#else
		_vmRecordBufs[i] = static_cast<uint8_t*>(std::malloc(POCKETDIAL_VOICEMAIL_MAX_MESSAGE_BYTES));
		_vmStagingBufs[i] = static_cast<uint8_t*>(std::malloc(POCKETDIAL_VOICEMAIL_MAX_MESSAGE_BYTES));
#endif
		if (_vmRecordBufs[i] == nullptr || _vmStagingBufs[i] == nullptr)
		{
			// Allocation failure at boot is a hardware/build-config problem,
			// not a runtime condition to recover from -- leave this leg's
			// buffers null and let the free-slot scan's null checks in
			// answerVoicemailDeposit() refuse deposits onto it rather than
			// crash. Every other leg still works.
			queueLog("[Voicemail] leg " + std::to_string(i) +
				" buffer allocation failed (" +
				std::to_string(POCKETDIAL_VOICEMAIL_MAX_MESSAGE_BYTES) + " bytes x2)", true);
		}
	}
	// Safe to call unconditionally (host included): std::fopen() against a
	// path that doesn't exist on this platform just returns null and the
	// function degrades gracefully, same as it does for "no card, no file
	// yet" on real hardware.
	loadVoicemailGreeting();

#if defined(PD_ETH_HAS_SD)
	// The SD-flush writer task -- mirrors CdrArchive.cpp's writerTaskBody
	// shape (poll the queue every 200ms, drain whatever's there) but spawned
	// HERE rather than from a free-function init(), since this queue and its
	// staging buffers are per-instance members, not a process-global
	// singleton like CdrArchive's. Captures `this` in a raw pointer, safe
	// because RequestsHandler is never destructed during normal operation on
	// a real device (same assumption CdrArchive's own never-terminating
	// writer task makes).
	xTaskCreatePinnedToCore([](void* arg) {
		auto* handler = static_cast<RequestsHandler*>(arg);
		for (;;)
		{
			handler->drainVoicemailFlush(vmarchive::productionSink());
			// Issue #246, retrieval slice 3/3: the same SD-I/O task also
			// serves list/read/delete jobs for a retrieval leg -- both are
			// SD-card work, and this task already exists for exactly that
			// discipline (never on the SIP/RTP threads). Runs every slot
			// each pass; a no-op for any slot not Pending.
			handler->runVoicemailSdJobs(vmarchive::productionSource());
			vTaskDelay(pdMS_TO_TICKS(200));
		}
	}, "vm_archive", 6144, this, 1, nullptr, 0);
	// Stack size is a reasoned estimate (FatFs snprintf/fopen/rename need
	// headroom, same order as CdrArchive's own 6144B figure), NOT measured
	// with uxTaskGetStackHighWaterMark() -- this task has never run on real
	// hardware. Flag for hardware bring-up, same as CdrArchive.cpp's
	// identical caveat on its own writer task.
#endif
}

RequestsHandler::~RequestsHandler()
{
#if !defined(ESP_PLATFORM) && !defined(ESP32)
	if (_anchorStartThread.joinable())
	{
		_anchorStartThread.join();
	}
	// Stage B: drain every outstanding asyncMakeCall/asyncDropCall/asyncAnswerCall
	// host worker BEFORE the anchor client is stopped and this object starts
	// tearing down — a still-running worker captured `this` and calls back into
	// _mutex/queueLog/endCall on completion, all of which need a live handler.
	reapAnchorWorkers(/*drainAll=*/true);
#endif
	// Stop the anchor BEFORE member destruction begins: LoopbackAnchorClient's
	// simulation threads call back into this handler (locking _mutex, touching
	// _sessions), and TelephonyAnchorClient's WS/media worker tasks are the same
	// kind of risk now that Stage B wires its event callback for a real anchor —
	// those members are destroyed before _loopbackClient/_telephonyAnchorClient
	// themselves, so relying on their own destructors to stop cleanly would be a
	// use-after-free (mirrors drawbridge's ~RequestsHandler exactly).
	if (_anchorClient)
	{
		_anchorClient->stop();
	}

	// Issue #246: free the voicemail buffer pool allocated in the
	// constructor. Symmetric ESP/host free matching the allocator above --
	// heap_caps_free() is safe to call on a null pointer (allocation
	// failure leaves it null), same as std::free().
	for (size_t i = 0; i < POCKETDIAL_MAX_VOICEMAIL_LEGS; ++i)
	{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
		heap_caps_free(_vmRecordBufs[i]);
		heap_caps_free(_vmStagingBufs[i]);
#else
		std::free(_vmRecordBufs[i]);
		std::free(_vmStagingBufs[i]);
#endif
	}
	if (_vmGreetingClipOwned)
	{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
		heap_caps_free(_vmGreetingClip);
#else
		std::free(_vmGreetingClip);
#endif
	}
}

// Same bounded-fallback bookkeeping for the virtual-peer pool as the message
// pool uses (SipMessagePool.cpp). Separate budget: a virtual peer is a
// long-lived per-park-slot stand-in, not a per-packet object.
static std::atomic<std::size_t> s_vpeerHeapFallbacksInFlight{0};

namespace
{
	// Same no-locking rule as SipMessagePool's HeapFallbackDeleter: the last
	// reference can drop while a pool-critical-section lock is held elsewhere,
	// so the deleter must not itself take any lock.
	struct VpeerFallbackDeleter
	{
		void operator()(SipClient* p) const noexcept
		{
			delete p;
			s_vpeerHeapFallbacksInFlight.fetch_sub(1, std::memory_order_relaxed);
		}
	};
}

// Forwarders onto the static pool in SipMessagePool.cpp (Issue #53 / #101(A) /
// #101(E)). Kept as public statics on RequestsHandler because SipMessageFactory,
// the handler table, and the test suite all call them by this name.
std::shared_ptr<SipMessage> RequestsHandler::getMessageFromPool(std::string_view message, sockaddr_in src)
{
	return sipmsgpool::getMessageFromPool(message, src);
}

std::shared_ptr<SipMessage> RequestsHandler::getMessageFromPool(const SipMessage& source)
{
	return sipmsgpool::getMessageFromPool(source);
}

void RequestsHandler::initHandlers()
{
	_handlers.emplace(SipMessageTypes::REGISTER,          std::bind(&RequestsHandler::onRegister,       this, std::placeholders::_1));
	_handlers.emplace(SipMessageTypes::OPTIONS,           std::bind(&RequestsHandler::onOptions,        this, std::placeholders::_1));
	_handlers.emplace(SipMessageTypes::CANCEL,            std::bind(&RequestsHandler::onCancel,         this, std::placeholders::_1));
	_handlers.emplace(SipMessageTypes::INVITE,            std::bind(&RequestsHandler::onInvite,         this, std::placeholders::_1));
	_handlers.emplace(SipMessageTypes::TRYING,            std::bind(&RequestsHandler::onTrying,         this, std::placeholders::_1));
	_handlers.emplace(SipMessageTypes::RINGING,           std::bind(&RequestsHandler::onRinging,        this, std::placeholders::_1));
	_handlers.emplace(SipMessageTypes::BUSY,              std::bind(&RequestsHandler::onBusy,           this, std::placeholders::_1));
	_handlers.emplace(SipMessageTypes::UNAVAILABLE,       std::bind(&RequestsHandler::onUnavailable,    this, std::placeholders::_1));
	_handlers.emplace(SipMessageTypes::OK,                std::bind(&RequestsHandler::onOk,             this, std::placeholders::_1));
	_handlers.emplace(SipMessageTypes::ACK,               std::bind(&RequestsHandler::onAck,            this, std::placeholders::_1));
	_handlers.emplace(SipMessageTypes::FINAL_FAILURE,     std::bind(&RequestsHandler::onFinalFailure,   this, std::placeholders::_1));
	_handlers.emplace(SipMessageTypes::BYE,               std::bind(&RequestsHandler::onBye,            this, std::placeholders::_1));
	_handlers.emplace(SipMessageTypes::REQUEST_TERMINATED,std::bind(&RequestsHandler::onReqTerminated,  this, std::placeholders::_1));
	_handlers.emplace(SipMessageTypes::REFER,             std::bind(&RequestsHandler::onRefer,          this, std::placeholders::_1));
	_handlers.emplace(SipMessageTypes::UPDATE,            std::bind(&RequestsHandler::onUpdate,         this, std::placeholders::_1));
	_handlers.emplace(SipMessageTypes::MESSAGE,           std::bind(&RequestsHandler::onMessage,        this, std::placeholders::_1));
	_handlers.emplace(SipMessageTypes::SUBSCRIBE,         std::bind(&RequestsHandler::onSubscribe,      this, std::placeholders::_1));
}

void RequestsHandler::handle(std::shared_ptr<SipMessage> request, std::string_view rawBytes)
{
	// Input validation: Drop null or structurally malformed packets instantly (SEC-02)
	if (!request || !request->isValidMessage())
	{
		_packetsDropped.fetch_add(1, std::memory_order_relaxed);
		return;
	}

	// Per-source IP rate limiting (Issue #38 / SEC-02) runs under its OWN lock,
	// BEFORE the big handler _mutex, so a flood from blocked IPs is dropped without
	// ever serializing on _mutex against legitimate signaling. ipAllowed/allowPacket
	// touch only the rate state, which _rateMutex now guards.
	{
		std::lock_guard<std::mutex> rlock(_rateMutex);
		if (!ipAllowed(request->getSource()) || !allowPacket(request->getSource()))
		{
			_packetsDropped.fetch_add(1, std::memory_order_relaxed);
			return;
		}
	}

	std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>> localOutbox;
	std::vector<std::pair<bool, std::string>> localLogs;
	{
		std::lock_guard<std::mutex> lock(_mutex);

		_packetsProcessed.fetch_add(1, std::memory_order_relaxed);
		_outbox.clear();

		// Issue #33: /api/pcap capture. Only messages that clear the checks above
		// (structurally valid, not rate-limited) are captured — this is a
		// signaling-research aid, not a wire-level DoS forensics tool, and
		// capturing before the rate limiter would mean pulling the ring buffer
		// out from under _mutex for every flood packet too.
		// Written straight into the ring slot — no per-packet temporary inside
		// the critical section (Issue #101(D)).
		std::string& pcapSlot = _pcapCapture.recordInto(/*outbound=*/false, request->getSource());
		if (!rawBytes.empty())
		{
			// Issue #105: capture the exact bytes recvfrom() delivered, not a
			// re-serialization of the parsed message — whitespace, compact header
			// forms (f:/t:/v:/i:), CRLF-vs-LF tolerance, or any malformed-but-
			// tolerated line the parser normalized must survive in the capture.
			pcapSlot.assign(rawBytes.data(), rawBytes.size());
		}
		else
		{
			// No wire bytes offered (a message built in-process, or a test calling
			// handle() directly with no UdpServer/SipServer involved) — the parsed
			// form is genuinely what such a caller means to inspect.
			request->toString(pcapSlot);
		}

		// ── SDP admission gate (docs/THREAT_MODEL.md T-7) ──────────────────────
		// Every SDP body is structurally checked HERE, once, before any handler
		// decodes it and before it can be relayed to a peer phone -- initial
		// INVITE, re-INVITE, UPDATE, ACK and every response alike. A well-formed
		// SIP start line says nothing about the body: the UNISOC T612 RCE rode in
		// on a normal MMTel video offer whose a= lines were the poison. The check
		// is one flat, allocation-free pass (SipMessage::checkSdp); a violation is
		// a hard error for the whole message, never "keep tokenizing". It sits
		// after the pcap capture on purpose, so the refused bytes are there to
		// look at.
		bool sdpRefused = false;
		// Set when the §17.2 server transaction answered this packet from its
		// stored response, which means the TU must not see it at all.
		bool absorbed   = false;
		if (request->hasSdp() && !request->getBody().empty())
		{
			const auto verdict = request->checkSdp();
			if (verdict != SipMessage::SdpVerdict::Ok)
			{
				rejectSdp(request, verdict);
				sdpRefused = true;
			}
		}

		auto client = findClientByAddress(request->getSource());
		if (client.has_value())
		{
			client.value()->markActive();
		}

		maybeSweep();

		// RFC 4733 key presses captured on the media tasks since the last pass.
		// Drained HERE as well as in tick() for two reasons: whenever any SIP
		// traffic is flowing a digit is acted on immediately instead of waiting
		// up to a tick, and it gives a host test a deterministic way to trigger
		// the drain — tick() self-throttles to 1 Hz, so calling it in a loop
		// proves nothing.
		drainDtmfInbox();

		// A refused SDP body skips the transaction layer and the handler table
		// entirely: a poison 200 OK must not "accept" an INVITE transaction any
		// more than it may be relayed. The pool slot is released with the shared_ptr
		// like any other unhandled packet.
		if (!sdpRefused)
		{
		// RFC 3261 §17 transaction layer, CLIENT half: advance the state machine
		// for any tracked client transaction before the TU handler runs. A 1xx
		// moves Calling → Proceeding (stops retransmitting an INVITE, caps the
		// interval at T2 for a non-INVITE); a 2xx/3xx-6xx → Accepted/Completed.
		_txLayer.matchAndAdvance(request);

		// RFC 3261 §17.2 transaction layer, SERVER half: a retransmitted request
		// this PBX has ALREADY answered is answered again from the stored
		// response, and the TU is not re-run.
		//
		// Re-running it is what turns one lost packet into a second action: a
		// retransmitted REFER transfers the call twice, a retransmitted INFO
		// doubles a DTMF digit, and a retransmitted BYE draws a 481 for a dialog
		// we tore down perfectly well the first time. The absorb also replaces
		// onInvite's older "Task 2A" silent-drop guard for the cases it covers —
		// silence made the phone keep retransmitting until ITS Timer B, where
		// re-sending our 180/200 ends the retransmission immediately.
		//
		// Returns false for ACK (which it consumes internally to stop a 2xx
		// retransmit, but must not swallow — onAck bridges media and completes
		// transfer splices) and for anything with no matching server transaction,
		// which is every first-arrival request.
		if (_txLayer.absorbRetransmittedRequest(request))
		{
			_packetsAbsorbed.fetch_add(1, std::memory_order_relaxed);
			queueLog("[tx] absorbed retransmitted " + std::string(request->getType())
				+ " for callID=" + std::string(request->getCallID())
				+ " — re-sent stored response", false);
			absorbed = true;
		}
		}

		// Anything a handler forwards by pushing THIS object (rather than a clone)
		// is a pass-through relay, not something the PBX sends on its own behalf.
		// drainOutbox() reads this to keep a retransmit timer off it; see the
		// member's declaration for why that matters.
		_passThroughMsg = request.get();

		if (!sdpRefused && !absorbed)
		{

		// Route responses by parsed numeric status code so dispatch is immune to
		// reason-phrase variation (e.g. "486 Busy" vs "486 Busy Here"). Requests and
		// anything without a status line fall back to the method/start-line token.
		std::string handlerKey;
		auto status = request->getStatusInfo();
		if (status.has_value())
		{
			switch (status->code)
			{
				case 100: handlerKey = SipMessageTypes::TRYING;             break;
				case 180: handlerKey = SipMessageTypes::RINGING;            break;
				case 200: handlerKey = SipMessageTypes::OK;                 break;
				case 480: handlerKey = SipMessageTypes::UNAVAILABLE;        break;
				case 486: handlerKey = SipMessageTypes::BUSY;               break;
				case 487: handlerKey = SipMessageTypes::REQUEST_TERMINATED; break;
				// Anything else with a final code: one shared key, so a 4xx/5xx/6xx
				// this table has no name for still reaches a handler. It used to
				// fall through to the full status line, match nothing, and be
				// dropped -- leaving a server-originated INVITE unACKed (RFC 3261
				// §17.1.1.3) and its dialog pinned until a timeout that then sent
				// an illegal post-final CANCEL. Provisional (1xx) and other 2xx
				// codes keep the old behaviour.
				default:
					handlerKey = (status->code >= 300)
						? SipMessageTypes::FINAL_FAILURE
						: std::string(request->getType());
					break;
			}
		}
		else
		{
			handlerKey = std::string(request->getType());
		}

		// Surface inbound client-error (4xx) responses once. Deferred via _logQueue
		// so the write happens outside the lock (Issue #24); replaces the per-parse
		// printf the parser used to do. softFail -> warning (stdout), else error (stderr).
		if (status.has_value() && status->klass == PocketDial::SipStatusClass::ClientError)
		{
			queueLog("[SIP] " + std::string(status->softFail ? "WARN " : "ERROR ")
				+ std::string(request->getHeader()), !status->softFail);
		}

		// Issue #402: every request's CSeq is a number the other party on its dialog
		// has now seen (in-dialog requests are relayed untouched), so any request the
		// server later sends on that dialog must go above it. Noted before dispatch,
		// so onRefer() already counts its own REFER, and again after, so an INVITE
		// that CREATES its session is counted too.
		std::string noteCallId;
		uint32_t noteCSeq = 0;
		const sockaddr_in noteSource = request->getSource();
		if (!status.has_value())
		{
			noteCallId = std::string(request->getCallID());
			noteCSeq = siphdr::cseqNumber(request->getCSeq());
			noteDialogCSeq(noteCallId, noteCSeq, noteSource);
		}

		// Task 2C: SIP INFO with DTMF relay body — handle before the handler table
		// so it is never mistakenly forwarded by a catch-all entry.
		if (handlerKey == "INFO")
		{
			// Scan headers for Content-Type: application/dtmf-relay.
			const std::string& rawMsg = request->toString();
			bool isDtmfRelay = false;
			{
				size_t pos = 0;
				while (pos < rawMsg.size())
				{
					size_t nl = rawMsg.find('\n', pos);
					size_t next = (nl == std::string::npos) ? rawMsg.size() : nl + 1;
					// Header/body boundary: blank line.
					if (pos < rawMsg.size() && (rawMsg[pos] == '\r' || rawMsg[pos] == '\n')) break;
					// Header name = text before the first ':' (RFC 3261: no WS before colon).
					size_t colon = rawMsg.find(':', pos); if (colon != std::string::npos && colon < ((nl == std::string::npos) ? rawMsg.size() : nl))
					{
						std::string nameLC = rawMsg.substr(pos, colon - pos);
						std::transform(nameLC.begin(), nameLC.end(), nameLC.begin(),
							[](unsigned char c){ return static_cast<char>(std::tolower(c)); });
						if (nameLC == "content-type" || nameLC == "c")
						{
							size_t valEnd = (nl == std::string::npos) ? rawMsg.size() : nl;
							std::string val = rawMsg.substr(colon + 1, valEnd - (colon + 1));
							if (val.find("application/dtmf-relay") != std::string::npos)
							{
								isDtmfRelay = true;
							}
							break;
						}
					}
					pos = next;
				}
			}
			// Always 200 OK a SIP INFO (RFC 6086 §4.2.1).
			{
				auto infoOk = getMessageFromPool(*request);
				if (!infoOk) return;   // pool exhausted: drop, peer retransmits (#101A)
				infoOk->setHeader(SipMessageTypes::OK);
				infoOk->setVia(sipwire::viaWithReceived(request->getVia(), request->getSource()));
				_outbox.emplace_back(request->getSource(), std::move(infoOk));
			}
			if (isDtmfRelay)
			{
				// Found in review (Fable-Low, during the retrieval slice's
				// design pass): this guard was previously ABSENT entirely,
				// so any voicemail leg's caller sending digits via SIP
				// INFO already leaked into the star-code parser instead --
				// a pre-existing gap affecting DEPOSIT legs too, not
				// something the retrieval menu introduces. RFC 4733 is the
				// only digit path this MVP's menu wires up (see
				// answerVoicemailRetrieval()'s DtmfSink); SIP INFO support
				// for it is an explicit follow-up, not an oversight.
				auto infoSession = findSession(request->getCallID());
				if (!infoSession || !infoSession->isVoicemail())
				{
					_dtmf.onInfo(request);
				}
			}
		}
		else
		{
			auto it = _handlers.find(handlerKey);
			if (it != _handlers.end())
			{
				it->second(std::move(request));
			}
		}
		noteDialogCSeq(noteCallId, noteCSeq, noteSource);
		}   // !sdpRefused

		// Device-registry change detection: a REGISTER may have adopted a device,
		// re-synced its extension, or flipped its online flag inside the Registrar
		// machine — mirror the registry into the dashboard snapshot once per packet.
		applyDeviceChange(_registrar.consumeDevicesChange());

		// Park-orbit change detection, same contract. Polling here (rather than
		// making every mutating call site remember refreshParkSnapshot()) means a
		// new park path cannot silently leave a stale row on the dashboard.
		if (_park.consumeParkChanged())
		{
			refreshParkSnapshot();
		}

		// BLF change detection: one pass after every handled packet covers
		// registration appear/disappear, session create/transition/teardown.
		// NOTIFYs land in _outbox and ride out with this pass (after unlock).
		_blf.refresh();

		localOutbox = drainOutbox();
		_passThroughMsg = nullptr;

		localLogs = std::move(_logQueue);
		_logQueue.clear();
	}

	// Print deferred logs safely outside of the lock
	for (const auto& log : localLogs)
	{
		if (log.first) std::cerr << log.second << '\n';
		else std::cout << log.second << '\n';
	}

	// Issue #24 resolved: UDP socket syscall sendto is now executed outside the locked section to prevent lock contention.
	for (auto& event : localOutbox)
	{
		_onHandled(event.first, std::move(event.second));
	}
}

void RequestsHandler::noteDialogCSeq(const std::string& callID, uint32_t cseq,
	const sockaddr_in& source)
{
	if (cseq == 0 || callID.empty()) return;
	auto s = findSession(callID);
	// Only a party ON this dialog moves its CSeq floor; Session also refuses
	// out-of-range values, which is the part a spoofed source can't get past.
	if (!s || !isDialogSourceAuthorized(s, source)) return;
	s->noteObservedCSeq(cseq);
}

std::optional<std::shared_ptr<Session>> RequestsHandler::getSession(std::string_view callID)
{
	auto sessionIt = _sessions.find(std::string(callID));
	if (sessionIt != _sessions.end())
	{
		return sessionIt->second;
	}
	return {};
}

void RequestsHandler::onRegister(std::shared_ptr<SipMessage> data)
{
	auto fromNumber = data->getFromNumber();
	int requestedExpires = parseRequestedExpires(data);
	int grantedExpires = 0;

	if (!isValidAor(fromNumber))
	{
		auto response = getMessageFromPool(*data);
		if (!response) return;   // pool exhausted: drop, peer retransmits (#101A)
		response->setHeader("SIP/2.0 400 Bad Request");
		response->clearBody();
		response->setVia(sipwire::viaWithReceived(data->getVia(), data->getSource()));
		_outbox.emplace_back(data->getSource(), std::move(response));
		return;
	}

	// ── Service extensions are not registerable (Issue #202) ─────────────────────
	// `pbx`, `moh` and `server` are identities the ENGINE originates as, and
	// isValidAor has always admitted them as spellings — std::isalnum plus
	// . - _ + * # — so nothing before this stopped a phone from REGISTERing under
	// one of them and taking the name. That is not a theoretical tidiness point:
	// the register-beep response paths deliberately rely on findClient("pbx")
	// MISSING (see onReqTerminated's comment on the stray 404 that results when it
	// doesn't), so a client bound to "pbx" would send 404s back at phones that had
	// just been beeped, and would put a fake handset in the dashboard roster.
	//
	// 403, not 400: the AOR is well-formed, it is the identity that is refused.
	// Placed BEFORE the registrar-mode admission so the refusal is the same in
	// Open, Secure and Learn — in particular a service name can never be ADOPTED
	// in Learn mode, which is one of the issue's explicit constraints. Refusing an
	// expires=0 de-REGISTER too is deliberate and harmless: there is nothing to
	// unbind, because no binding under that name can ever have been created.
	if (pbx::isServiceName(fromNumber))
	{
		queueLog("REGISTER refused: \"" + std::string(fromNumber) +
			"\" is a reserved service extension", true);
		_registrar.sendForbidden(data, "Reserved service extension");
		return;
	}

	// ── Reserved/emergency/PSTN-shaped identity guard (Issue #163) ───────────────
	// isValidAor() above is charset-only, so nothing stopped a phone REGISTERing
	// as a reserved virtual extension (777/999/888/555/440 — colliding directly
	// with the echo test, all-page, meet-me conference, anchor media bridge or
	// busy tone), as 911 or 933 (no special handling exists for either anywhere
	// in this codebase, so a squatter would silently receive calls meant for
	// them), or as an E.164/PSTN-shaped number. See pbx::isReservedOrPstnAor()
	// (PbxConfig.hpp) for the full reasoning behind each case.
	//
	// Same placement rationale as the service-name guard just above: BEFORE the
	// registrar-mode admission so Open/Secure/Learn all refuse identically, and
	// 403 (not 400) because the AOR is well-formed — it is the identity that is
	// refused.
	if (pbx::isReservedOrPstnAor(fromNumber))
	{
		queueLog("REGISTER refused: \"" + std::string(fromNumber) +
			"\" is a reserved, emergency or PSTN-shaped identity", true);
		_registrar.sendForbidden(data, "Reserved or PSTN-shaped extension");
		return;
	}

	// ── Registrar-mode admission (STAGE 2) ───────────────────────────────────────
	// Runtime policy replaces the old compile-time POCKETDIAL_OPEN_REGISTRAR gate.
	//   Open   : accept every REGISTER (legacy standalone behaviour).
	//   Secure : digest-challenge + verify against the stored HA1 for this ext.
	//   Learn  : TOFU + MAC-lock — adopt unknown devices, enforce secured ones.
	// On Challenge the helper has already enqueued the 401 + WWW-Authenticate; on
	// Reject we emit the 403 here from rejectReason. Either way a non-Accept stops.
	const std::string extStr(fromNumber);
	const RegistrarMode mode = _registrar.getMode();
	if (mode != RegistrarMode::Open)
	{
		std::string rejectReason;
		Registrar::AuthDecision decision = (mode == RegistrarMode::Secure)
			? _registrar.admitSecure(data, extStr, rejectReason)
			: _registrar.admitLearn(data, extStr, rejectReason);

		if (decision == Registrar::AuthDecision::Challenge)
		{
			// admitSecure already enqueued the 401 + WWW-Authenticate.
			return;
		}
		if (decision == Registrar::AuthDecision::Reject)
		{
			_registrar.sendForbidden(data, rejectReason.empty() ? "Forbidden" : rejectReason);
			return;
		}
		// decision == Accept → fall through to the normal binding path below.
	}

	// Resolve the device MAC once (Learn/registry bookkeeping). nullopt on a
	// first-packet ARP miss or on host — the online flag just stays unchanged then.
	std::optional<std::string> deviceMac;
	{
		auto m = ArpLookup::pdLookupMac(data->getSource());
		if (m.has_value()) deviceMac = ArpLookup::toHex12(*m);
	}

	if (requestedExpires <= 0)
	{
		// expires=0 (or an explicit zero) is a de-registration request.
		unregisterClient(fromNumber);
		if (deviceMac.has_value()) _registrar.markOnline(*deviceMac, false);
	}
	else
	{
		grantedExpires = (std::max)(MIN_EXPIRES, (std::min)(requestedExpires, MAX_EXPIRES));
		// Distinguish a brand-new binding from a lease refresh BEFORE allocating: a
		// client already present in the pool under this number is a re-REGISTER, which
		// must NOT trigger a welcome MESSAGE (phones re-register every lease period).
		bool isNewBinding = !findClient(fromNumber).has_value();
		// Always update address so re-REGISTER after a NAT rebind works correctly
		auto newClient = allocateClient(std::string(data->getFromNumber()), data->getSource(), grantedExpires);
		if (newClient)
		{
			// allocateClient() has already placed the binding in the client pool;
			// the registrar keeps no separate index, so there is nothing more to do
			// here (this was previously a no-op registerClient() hook).
			// Register beep: on a brand-new binding ONLY (never a lease refresh —
			// phones re-REGISTER every lease period), send the registering phone a
			// brief intercom auto-answer INVITE so it plays its own tone, then tear
			// the call back down. Signaling-only: the server sources NO RTP. Bounded
			// and best-effort — if the beep table is full the beep is simply skipped.
			if (isNewBinding)
			{
				_beeper.sendBeep(newClient);
			}
			if (deviceMac.has_value()) _registrar.markOnline(*deviceMac, true);
		}
		else
		{
			// Server full: reply with 503 Service Unavailable
			auto response = getMessageFromPool(*data);
			if (!response) return;   // pool exhausted: drop, peer retransmits (#101A)
			response->setHeader("SIP/2.0 503 Service Unavailable");
			response->clearBody();
			response->setVia(sipwire::viaWithReceived(data->getVia(), data->getSource()));
			_outbox.emplace_back(data->getSource(), std::move(response));
			return;
		}
	}

	auto response = getMessageFromPool(*data);
	if (!response) return;   // pool exhausted: drop, peer retransmits (#101A)
	response->setHeader(SipMessageTypes::OK);
	response->setVia(sipwire::viaWithReceived(data->getVia(), data->getSource()));
	response->setTo(std::string(data->getTo()) + ";tag=" + IDGen::GenerateID(9));
	// Echo the granted lease back in the Contact so the client knows when to refresh.
	response->setContact(buildContact(fromNumber) + ";expires=" + std::to_string(grantedExpires));
	// The registrar's 200 OK is the one message EVERY phone sees, on every lease
	// period, before it ever places a call — which makes it the discovery point
	// that matters most in practice. OPTIONS only tells a phone that bothers to
	// ask; plenty never do, and a phone that has not learned `Supported:
	// replaces` here will not offer a Replaces-based attended transfer via
	// REFER (issue #131) -- NOT BLF-key pickup, which needs an INVITE that
	// itself carries Replaces and has no handler here (issue #229).
	//
	// The PBX is unambiguously the UAS of a REGISTER, so there is no relay
	// question on this path.
	addCapabilityHeaders(*response);
	endHandle(fromNumber, response);
}

// ── Capability advertisement (issue #199, root cause 2) ──────────────────────
// Until this landed, no code in src/ ever emitted Allow:, Supported: or Accept:.
// Two concrete consequences, both of which make a correctly-implemented phone
// refuse to use machinery this PBX already has:
//   * RFC 3311 §5.1 — a UA MUST NOT send an UPDATE unless the peer advertised
//     UPDATE in an Allow header. onUpdate() has handled hold/resume and bodiless
//     session-timer keep-alives all along; no phone would ever reach it.
//   * RFC 3891 §4 — a UA only offers a Replaces-based ATTENDED TRANSFER (REFER
//     with a ?Replaces= Refer-To, issue #131) when the peer advertised
//     "replaces" in Supported. onRefer()'s splice was likewise unreachable
//     from a spec-abiding phone.
//
// "replaces" does NOT cover RFC 3891's other use of the same tag: a UA sending
// an INVITE that itself carries a Replaces header (§3), the mechanism behind
// BLF-key "grab this ringing call" pickup and phone-native call steal. No code
// in src/ handles that -- onInvite() has no Replaces branch, so such an INVITE
// just rings its own target as an ordinary new call (ReplacesInvite_test.cpp
// pins this).
//
// This is a KNOWN, DELIBERATE SPEC DEVIATION, not merely an unimplemented
// corner: RFC 3891 §3 says a UA that advertises "replaces" MUST accept an
// INVITE carrying that header, and this one advertises it while only actually
// honouring §4's REFER-based use of the same tag. Withdrawing the tag would
// break the working, exercised attended transfer (REFER ?Replaces=, issue
// #131) for no gain, so issue #229 chose to keep advertising and document the
// gap rather than under-claim a real feature to fix an unrelated one. See
// kSupportedOptionTags below.
//
// EVERY entry below is something this PBX genuinely dispatches. Over-claiming is
// the exact failure #199 is about, so the lists are derived from initHandlers()
// (:582-601) plus the one method handled ahead of the table, and nothing else.
namespace
{
	// The request methods initHandlers() registers — REGISTER, OPTIONS, CANCEL,
	// INVITE, ACK, BYE, REFER, UPDATE, MESSAGE, SUBSCRIBE — plus INFO, which
	// handle() answers before the handler table (RFC 6086 §4.2.1) and routes to
	// the DTMF collector. The other table entries (TRYING/RINGING/BUSY/
	// UNAVAILABLE/OK/FINAL_FAILURE/REQUEST_TERMINATED) are RESPONSE keys, not
	// methods, and have no business in Allow.
	//
	// Deliberately absent: PRACK (no handler — so 100rel must not be claimed
	// either), NOTIFY (BlfSubscriptions SENDS them; nothing accepts one) and
	// PUBLISH. A phone that saw those here would wait on replies we never send.
	constexpr const char* kAllowedMethods =
		"INVITE, ACK, CANCEL, BYE, OPTIONS, REGISTER, INFO, MESSAGE, REFER, "
		"SUBSCRIBE, UPDATE";

	// Option tags, RFC 3261 §20.37. "replaces" only.
	//
	// "replaces" is PARTIAL -- see the capability-advertisement block above
	// this namespace for the full reasoning. Short form: it backs onRefer()'s
	// REFER ?Replaces= attended-transfer splice (#131); it does NOT mean an
	// INVITE carrying a Replaces header itself (§3, BLF-key pickup) is
	// handled, because nothing in src/ reads that header. Kept per #229's
	// scope call rather than withdrawn, since the REFER usage is real.
	//
	// NOT "timer": docs/FEATURE_ROADMAP.md calls the RFC 4028 support "passive —
	// honours a timer a phone requests, but never requests one itself and never
	// sends 422/Min-SE". §5 and §6 make Min-SE processing and the 422 response
	// mandatory for an entity that advertises the extension, and neither exists
	// here (getMinSESecs() has no caller), so advertising it would be a lie.
	// NOT "100rel" (RFC 3262 needs PRACK), "norefersub", "path", "gruu" or
	// "outbound" — none of them have any implementation in this codebase.
	constexpr const char* kSupportedOptionTags = "replaces";

	// Body types this PBX actually parses: SDP on INVITE/re-INVITE/UPDATE/ACK,
	// and the DTMF relay body handle() looks for on INFO. onMessage() does not
	// interpret its body at all (RequestsHandler.cpp:3940-3944), so no MESSAGE
	// content type is claimed — under-claiming is the safe direction here.
	constexpr const char* kAcceptedBodyTypes = "application/sdp, application/dtmf-relay";
}

// Stamp this PBX's own capabilities onto a message it AUTHORED.
//
// ── Only ever on messages this PBX authors ───────────────────────────────────
//
// Never on a relayed one. For an ordinary extension-to-extension call this
// engine is a forwarding proxy / forked-UAC hybrid, not a B2BUA: callee B's 200
// OK reaches caller A almost verbatim, carrying B's OWN Allow/Supported. Writing
// this PBX's list over B's would tell A that B accepts UPDATE and understands
// `replaces` on the strength of the PBX supporting them — a claim about the far
// end that the PBX is in no position to make. That is the same dishonesty the
// `timer` exclusion below refuses to commit, so the rule is applied
// symmetrically: authored messages only. The same boundary governs which
// responses earn a server transaction (TransactionLayer::authoredHere).
//
// ── setHeaderOnce, not addHeader ─────────────────────────────────────────────
//
// Responses here are built by CLONING the request, and getMessageFromPool(const
// SipMessage&) copies every header line — so a phone that put `Allow:` in its
// own REGISTER has already put an Allow line in our 200 OK before we get here.
// addHeader() appends unconditionally and would emit both, which reads on the
// wire as one merged capability set belonging to nobody. setHeaderOnce()
// replaces, leaving exactly one line.
void RequestsHandler::addCapabilityHeaders(SipMessage& response) const
{
	response.setHeaderOnce("Allow", kAllowedMethods);
	response.setHeaderOnce("Supported", kSupportedOptionTags);
	response.setHeaderOnce("Accept", kAcceptedBodyTypes);
	// RFC 6665 §4.4.1: a UA that accepts SUBSCRIBE advertises its packages.
	// BlfSubscriptions::onSubscribe() implements exactly one, the RFC 4235
	// "dialog" package, and 489s anything else (BlfSubscriptions.cpp:145-154).
	response.setHeaderOnce("Allow-Events", "dialog");
}

void RequestsHandler::onOptions(std::shared_ptr<SipMessage> data)
{
	auto response = getMessageFromPool(*data);
	if (!response) return;   // pool exhausted: drop, peer retransmits (#101A)
	response->setHeader(SipMessageTypes::OK);
	response->setVia(sipwire::viaWithReceived(data->getVia(), data->getSource()));
	response->setTo(std::string(data->getTo()) + ";tag=" + IDGen::GenerateID(9));
	response->setContact(buildContact(data->getFromNumber()));
	// OPTIONS is THE capability-discovery method (RFC 3261 §11.2: a 200 OK to it
	// SHOULD carry Allow/Accept/Supported), and it is the one a phone polls as a
	// keep-alive — so this is where the advertisement costs nothing and is read.
	addCapabilityHeaders(*response);
	_outbox.emplace_back(data->getSource(), std::move(response));
}

void RequestsHandler::onCancel(std::shared_ptr<SipMessage> data)
{
	std::string destNumber(data->getToNumber());
	auto cancelSess = getSession(data->getCallID());

	// Issue #46: same off-path teardown guard as onBye(). A CANCEL whose Call-ID
	// names an established two-leg dialog must come from a leg IP.
	if (cancelSess.has_value() &&
		!isDialogSourceAuthorized(cancelSess.value(), data->getSource()))
	{
		queueLog("CANCEL for Call-ID " + std::string(data->getCallID()) +
			" rejected: source not a dialog leg (spoofed teardown)", true);
		_registrar.sendForbidden(data, "Forbidden");
		return;
	}

	if (destNumber == "777")
	{
		endCall(data->getCallID(), data->getFromNumber(), "777");
		return;
	}

	if (destNumber == "440")
	{
		// CANCEL of the media call: stop the stream (if it owns this Call-ID) and end.
		_rtpSender.stop(std::string(data->getCallID()));
		endCall(data->getCallID(), data->getFromNumber(), "440");
		return;
	}

	if (destNumber == ConferenceRoom::EXT)
	{
		// CANCEL of a conference dial-in: endCall() drops the leg (see its
		// ConferenceRoom::leave call), so the room needs nothing extra here.
		endCall(data->getCallID(), data->getFromNumber(), ConferenceRoom::EXT);
		return;
	}

	// A dial-plan Trunk rule (Issue #165) originates an anchor call under
	// whatever digits the caller actually dialed (e.g. "92025550123"), not the
	// literal 555 feature code — CANCEL must match the original INVITE's
	// Request-URI verbatim (RFC 3261 §9.1), so destNumber above is that dialed
	// string, not "555". Recognize the session by its own isAnchor() flag as well
	// as the literal code, or a trunk-dialed CANCEL falls through to the generic
	// findClient(destNumber) path below, which never finds a registered peer for
	// a dialed PSTN number, answers 404, and never calls endCall() — leaking the
	// MediaBridge and the live carrier leg. isAnchorInbound() sessions (ring-all
	// from a real PSTN inbound call) are excluded: their teardown is unrelated.
	if (destNumber == kAnchorCallExt ||
		(cancelSess.has_value() && cancelSess.value()->isAnchor() && !cancelSess.value()->isAnchorInbound()))
	{
		// CANCEL of an anchor-bridge dial-in. For Loopback (answers synchronously,
		// no ringing window) this is mostly defensive symmetry with 777/440/888 —
		// but a real anchor (Stage B) rings first via asyncMakeCall(), so a caller
		// hanging up before the far leg connects is a real, commonly-hit race now.
		// RFC 3261 §9.2: the CANCEL request itself gets its own 200 OK (separate
		// from whatever final response, if any, the original INVITE transaction
		// gets) — a UA that never sees this retransmits the CANCEL. endCall()
		// (below) drops the anchor-side leg (async or sync, per
		// anchorIsSynchronous()) and releases the MediaBridge.
		auto response = getMessageFromPool(*data);
		if (response)
		{
			response->setHeader(SipMessageTypes::OK);
			response->clearBody();
			response->setVia(sipwire::viaWithReceived(data->getVia(), data->getSource()));
			_outbox.emplace_back(data->getSource(), std::move(response));
		}
		endCall(data->getCallID(), data->getFromNumber(), destNumber, "handset CANCEL");
		return;
	}

	if (_park.orbitIndex(destNumber) >= 0)
	{
		endCall(data->getCallID(), data->getFromNumber(), destNumber);
		return;
	}

	if (destNumber == "999" || _cfg.isPageZoneDialog(destNumber))
	{
		auto session = getSession(data->getCallID());
		if (session.has_value())
		{
			std::string activeIp = _localIp;
			std::string serverIpPort = activeIp + ":" + std::to_string(_serverPort);
			std::string originalCSeq(data->getCSeq());
			size_t invitePos = originalCSeq.find("INVITE");
			if (invitePos != std::string::npos)
			{
				originalCSeq.replace(invitePos, 6, "CANCEL");
			}

			for (const auto& target : session.value()->getPendingTargets())
			{
				auto cancelMsg = getMessageFromPool(*data);
				if (!cancelMsg) continue;   // pool exhausted: skip this target (#101A)
				std::string targetIpPort = sipwire::addrToIpPort(target->getAddress());

				cancelMsg->setHeader("CANCEL sip:" + target->getNumber() + "@" + targetIpPort + " SIP/2.0");

				std::string newTo = "To: <sip:" + target->getNumber() + "@" + serverIpPort + ">";
				cancelMsg->setTo(newTo);
				cancelMsg->setCSeq(originalCSeq);
				_outbox.emplace_back(target->getAddress(), std::move(cancelMsg));
			}
		}
		endCall(data->getCallID(), data->getFromNumber(), destNumber);
		return;
	}

	setCallState(data->getCallID(), Session::State::Cancel);
	endHandle(data->getToNumber(), data);
}

void RequestsHandler::onReqTerminated(std::shared_ptr<SipMessage> data)
{
	// A 487 to our own register-beep INVITE — the phone's answer to the CANCEL
	// sweep() sent when it never auto-answered (drawbridge #90/#178). Claim it
	// here exactly as onFinalFailure() does: 487 has its own handlerKey in
	// handle()'s dispatch switch, so it never reaches that catch-all, and the
	// beep guard was wired into the catch-all alone. Unclaimed, this fell
	// through to endHandle(data->getFromNumber(), ...) below — and a beep's From
	// is the server's own <sip:pbx@...> (RegisterBeeper::sendBeep), which is not
	// a registered extension, so findClient("pbx") missed and endHandle's else
	// branch minted a 404 Not Found straight back at the phone that had just
	// been beeped. The 487 also went unACKed, which RFC 3261 §17.1.1.3 requires,
	// leaving the phone retransmitting it until Timer H (~32 s).
	// Issue #164: a response to OUR trunk INVITE belongs to SipTrunk's dialog
	// machine, not to any session branch below -- the trunk leg is a
	// server-originated UAC with no handset Session of its own, so those
	// branches could not claim it anyway. Same intercept position as the
	// beeper's, for the same reason.
	if (_sipTrunk.handleResponse(data)) return;

	if (_beeper.handleInviteFailure(data))
	{
		return;
	}

	// The MoH preview is the same kind of dialog and needs the same claim.
	if (handleMohPreviewFailure(data))
	{
		return;
	}

	// Both claims must run: they match different Call-IDs, so neither can
	// mask the other, and dropping either sends its dialog back through
	// endHandle() -- whose lookup of a server-owned From matches no
	// registered client, so the else branch answers the phone with a stray
	// 404. MoH is first only because it reached main first.
	// A blind-transfer target refusing the INVITE the server sent on the
	// transferee's behalf (issue #197). Claimed here, ahead of every session
	// branch, for the same reason a beep dialog is: the server is that leg's UAC,
	// so the ACK is ours (RFC 3261 §17.1.1.3), and nothing further down reads the
	// response as what it actually is — onBusy()'s CFB lookup used to read
	// data->getFromNumber() here, which on this leg is the TRANSFEREE, not the
	// busy party; fixed to data->getToNumber() by #256. This intercept still
	// stands regardless, for the ACK-ownership reason above.
	if (handleBlindXferFailure(data))
	{
		return;
	}

	auto session = getSession(data->getCallID());
	if (session.has_value() && session.value()->isBroadcast())
	{
		return;
	}
	// Inbound anchor ring-all: a 487 is a forked loser's reply to the CANCEL sent
	// when another leg won (or on teardown). Complete the cancelled INVITE
	// transaction with an ACK — there is no caller to relay it to.
	if (session.has_value() && session.value()->isAnchorInbound())
	{
		ackInboundFinal(session.value(), data);
		return;
	}
	endHandle(data->getFromNumber(), data);
}

void RequestsHandler::onFinalFailure(std::shared_ptr<SipMessage> data)
{
	// Server-originated UAC dialogs have no Session -- they are owned by the
	// machine that minted them and found by Call-ID, the same intercept order
	// onOk() uses. Whoever claims it is responsible for the ACK (RFC 3261
	// §17.1.1.3) and for releasing its slot.
	// Issue #164: a response to OUR trunk INVITE belongs to SipTrunk's dialog
	// machine, not to any session branch below -- the trunk leg is a
	// server-originated UAC with no handset Session of its own, so those
	// branches could not claim it anyway. Same intercept position as the
	// beeper's, for the same reason.
	if (_sipTrunk.handleResponse(data)) return;

	if (_beeper.handleInviteFailure(data))
	{
		return;
	}

	// The MoH preview is the same kind of dialog and needs the same claim.
	if (handleMohPreviewFailure(data))
	{
		return;
	}

	// Both claims must run: they match different Call-IDs, so neither can
	// mask the other, and dropping either sends its dialog back through
	// endHandle() -- whose lookup of a server-owned From matches no
	// registered client, so the else branch answers the phone with a stray
	// 404. MoH is first only because it reached main first.
	// A blind-transfer target refusing the INVITE the server sent on the
	// transferee's behalf (issue #197). Claimed here, ahead of every session
	// branch, for the same reason a beep dialog is: the server is that leg's UAC,
	// so the ACK is ours (RFC 3261 §17.1.1.3), and nothing further down reads the
	// response as what it actually is — onBusy()'s CFB lookup used to read
	// data->getFromNumber() here, which on this leg is the TRANSFEREE, not the
	// busy party; fixed to data->getToNumber() by #256. This intercept still
	// stands regardless, for the ACK-ownership reason above.
	if (handleBlindXferFailure(data))
	{
		return;
	}

	// Nothing owns it: a failure on a relayed leg, already handled by the
	// endHandle()/session paths, or a stray. Recorded, not acted on -- the 4xx
	// log line above (ClientError) has already surfaced it to the operator.
	queueLog("[SIP] unclaimed final response " + std::string(data->getHeader())
		+ " for callID=" + std::string(data->getCallID()), false);
}

void RequestsHandler::onInvite(std::shared_ptr<SipMessage> data)
{
	// Task 2A: Retransmission guard — silently drop if a session for this Call-ID
	// is already active (Invited or Connected). RFC 3261 §17.2.3: a UAS that receives
	// a retransmission of a request for which a non-2xx final response has been sent
	// should retransmit that response; for 2xx, the ACK re-drive handles it. The
	// simplest safe policy here is a silent drop so we never create a second session
	// slot for the same dialog, which could exhaust the pool and trigger spurious 503.
	if (auto existing = getSession(data->getCallID()); existing.has_value())
	{
		const auto st = existing.value()->getState();
		// Mid-dialog re-INVITE (RFC 3261 §12.2): To-tag present = established dialog.
		// This is the hold/resume path — route to onReinvite().
		if ((st == Session::State::Connected || st == Session::State::Held) &&
			std::string_view(data->getTo()).find("tag=") != std::string_view::npos)
		{
			onReinvite(data);
			return;
		}
		if (st == Session::State::Invited || st == Session::State::Connected ||
			st == Session::State::Held)
		{
			return; // silent drop per RFC 3261 §17.2.3
		}
	}

	if (!isValidAor(data->getFromNumber()) || !isValidAor(data->getToNumber()))
	{
		auto response = getMessageFromPool(*data);
		if (!response) return;   // pool exhausted: drop, peer retransmits (#101A)
		response->setHeader("SIP/2.0 400 Bad Request");
		response->clearBody();
		response->setVia(sipwire::viaWithReceived(data->getVia(), data->getSource()));
		_outbox.emplace_back(data->getSource(), std::move(response));
		return;
	}

	// Check if the caller is registered
	auto caller = findClient(data->getFromNumber());
	if (!caller.has_value())
	{
		auto response = getMessageFromPool(*data);
		if (!response) return;   // pool exhausted: drop, peer retransmits (#101A)
		response->setHeader("SIP/2.0 403 Forbidden");
		response->clearBody();
		response->setVia(sipwire::viaWithReceived(data->getVia(), data->getSource()));
		_outbox.emplace_back(data->getSource(), std::move(response));
		return;
	}

	// Codec gate, before any session is allocated: an offer with no audio codec
	// this PBX will relay (Opus-only, G.729-only ...) gets a clean 488 now,
	// instead of a 200 OK whose rewritten m-line advertised payloads the phone
	// never offered -- the "signalling completes, media is dead" failure
	// PHONE_COMPATIBILITY.md used to document as a phone-side setting.
	if (data->hasSdp() && !data->offersSupportedAudio(/*allowWideband=*/true))
	{
		auto response = getMessageFromPool(*data);
		if (!response) return;   // pool exhausted: drop, peer retransmits (#101A)
		response->setHeader("SIP/2.0 488 Not Acceptable Here");
		response->clearBody();
		response->addHeader("Warning", "304 " + _localIp + " \"No compatible audio codec (PCMU/PCMA/G722)\"");
		response->setVia(sipwire::viaWithReceived(data->getVia(), data->getSource()));
		_outbox.emplace_back(data->getSource(), std::move(response));
		return;
	}

	std::string destNumber(data->getToNumber());

	// ── Emergency dialing, before anything an operator can configure (#166) ──
	//
	// This is the FIRST destination check in onInvite, ahead of the reserved
	// virtual extensions, ring groups and the dial plan. That ordering is the
	// whole feature, not a style choice — see EmergencyCall.hpp for why a
	// dial-plan rule cannot be trusted to carry 911 (an operator's "9*" +
	// stripDigits=1 outside-line rule silently rewrites a dialed 911 into 11).
	//
	// It also sits deliberately ABOVE the secure-mode challenge below, so
	// call-setup policy cannot block 911 — while staying BELOW the registration
	// and codec gates above, which are not policy: a caller this PBX cannot
	// identify or cannot relay audio for has no working call to place. See
	// EmergencyCall.hpp's "capability gates stay, policy gates do not".
	if (const pbx::EmergencyDial emergency = pbx::classifyEmergencyDial(destNumber);
		emergency.isEmergency)
	{
		routeEmergencyCall(data, caller.value(), emergency, destNumber);
		return;
	}

	// Secure mode: registration auth alone leaves call setup open to anyone who
	// can reach UDP/5060 (drawbridge #125). Challenge the INVITE with the same
	// digest machinery -- admitSecure() takes the method from the request line,
	// so it verifies against INVITE. The stateless 401 needs no session; the
	// credentialed retry arrives with CSeq+1 and falls through here. Learn mode
	// keeps its TOFU semantics and Open mode never challenges.
	if (_registrar.getMode() == RegistrarMode::Secure)
	{
		std::string rejectReason;
		const Registrar::AuthDecision decision =
			_registrar.admitSecure(data, std::string(data->getFromNumber()), rejectReason);
		if (decision == Registrar::AuthDecision::Challenge) return;   // 401 enqueued
		if (decision == Registrar::AuthDecision::Reject)
		{
			_registrar.sendForbidden(data, rejectReason.empty() ? "Forbidden" : rejectReason);
			return;
		}
	}

	if (destNumber == "777")
	{
		// The echo leg is SERVER-terminated and speaks G.711 only, so it is
		// narrower than the relay-level gate at the top of this function (which
		// admits G.722 because a peer-to-peer pair may negotiate wideband between
		// themselves). A caller offering nothing but wideband gets 488 here rather
		// than an answer advertising a codec this leg will never encode.
		//
		// Issue #304: PCMA is rejected too. Nothing in this codebase decodes
		// A-law (RtpReceiver.cpp only recognizes PAYLOAD_TYPE_PCMU; anything
		// else falls through to the DTMF-event check and is dropped), so a
		// PCMA-only offer admitted here would echo back as a 200 OK the peer
		// could never actually be heard over.
		if (data->hasSdp() && !data->offersSupportedAudio(/*allowWideband=*/false, /*allowPcma=*/false))
		{
			auto responseObj = getMessageFromPool(*data);
			if (!responseObj) return;   // pool exhausted: drop, peer retransmits (#101A)
			responseObj->setHeader("SIP/2.0 488 Not Acceptable Here");
			responseObj->clearBody();
			responseObj->setVia(sipwire::viaWithReceived(data->getVia(), data->getSource()));
			responseObj->setContact(buildContact("777"));
			_outbox.emplace_back(data->getSource(), std::move(responseObj));
			return;
		}

		// SDP loopback echo test. Issue #115: allocateSession() must be called
		// FIRST, before any 180/200 is built, mirroring the ordinary call-to-call
		// INVITE path below (and the hunt-group path above) — otherwise a full
		// session pool still gets a "successful" 200 OK with no _sessions entry
		// backing it, silently bypassing POCKETDIAL_MAX_SESSIONS.
		auto newSession = allocateSession(std::string(data->getCallID()), caller.value());
		if (!newSession)
		{
			auto responseObj = getMessageFromPool(*data);
			if (!responseObj) return;   // pool exhausted: drop, peer retransmits (#101A)
			responseObj->setHeader("SIP/2.0 503 Service Unavailable");
			responseObj->clearBody();
			responseObj->setContact(buildContact(caller.value()->getNumber()));
			_outbox.emplace_back(data->getSource(), std::move(responseObj));
			return;
		}

		// Draw BOTH responses before publishing the session (mirrors the 440 media
		// path's "OK drawn before the session is published" comment above
		// onMediaInvite): once _sessions.emplace()+Connected below has run, a
		// message-pool refusal here would abandon a dialog with no 180/200 ever
		// sent and no clean way back (the retransmission guard at the top of this
		// function would then silently drop the caller's retry). Refusing now, before
		// either mutation, leaves nothing behind — allocateSession() already reset
		// newSession's Call-ID but never published it to _sessions, so the next
		// allocateSession() call reclaims this same slot as free (see its scan for a
		// slot whose Call-ID is absent from _sessions).
		auto ringing = getMessageFromPool(*data);
		if (!ringing) return;   // pool exhausted: drop, peer retransmits (#101A)
		auto okResponse = getMessageFromPool(*data);
		if (!okResponse) return;   // pool exhausted: drop, peer retransmits (#101A)

		// Per-session dummy dest (never the old shared _dummyClient): a concurrent
		// 777/440 call must not overwrite this session's destination identity. The
		// shared_ptr lives as long as the session references it (released on
		// teardown / pool reuse) — bounded by the session pool, not the packet path.
		//
		// Drawn from _virtualPeerPool rather than make_shared'd here (drawbridge
		// audit #70). This is the UDP packet handler, and invariant 1 — zero heap
		// allocation in the packet hot path — says every transient SipClient comes
		// from a boot-time pool; park/conference/anchor/PSTN already do, and
		// PoolConfig.hpp:121-126 has described 777 as pool-drawn all along. The
		// pool is sized POCKETDIAL_MAX_SESSIONS + POCKETDIAL_PARK_SLOTS, so the
		// allocateSession() above is the real gate and this should never fail —
		// but unlike drawbridge's allocator, which always heap-falls-back, ours
		// returns nullptr past POCKETDIAL_VPEER_HEAP_FALLBACK_MAX, so the null
		// MUST be checked: setDest(nullptr) would publish a Connected session
		// whose teardown/CDR paths dereference getDest(). Refuse with the same
		// 503 the session-pool-full branch above sends, and refuse HERE, before
		// setDest()/_sessions.emplace() — newSession is still unpublished, so the
		// next allocateSession() reclaims its slot (see that comment above).
		auto dummy777 = allocateVirtualPeer("777", data->getSource());
		if (!dummy777)
		{
			auto responseObj = getMessageFromPool(*data);
			if (!responseObj) return;   // pool exhausted: drop, peer retransmits (#101A)
			responseObj->setHeader("SIP/2.0 503 Service Unavailable");
			responseObj->clearBody();
			responseObj->setContact(buildContact("777"));
			_outbox.emplace_back(data->getSource(), std::move(responseObj));
			queueLog("777 echo: virtual-peer pool exhausted, rejected "
				+ std::string(data->getFromNumber()), true);
			return;
		}
		newSession->setDest(dummy777);
		_sessions.emplace(data->getCallID(), newSession);
		newSession->setState(Session::State::Connected);

		ringing->setHeader("SIP/2.0 180 Ringing");
		ringing->clearBody();
		ringing->setVia(sipwire::viaWithReceived(data->getVia(), data->getSource()));
		std::string toTag = IDGen::GenerateID(9);
		// Issue #232: this leg is server-terminated (the PBX is the UAS, answering
		// itself — there is no far-end phone whose 200 OK the ordinary onOk() path
		// at :4454 could capture headers from), so this is the only place this
		// leg's own dialog identity is ever known. Record it on the Session or
		// getDialogFrom()/getDialogTo() stay empty forever and the #72 guard in
		// forceDisconnect()/sweepSessionTimers() can never build a BYE toward this
		// handset if the call is torn down from the server side. Same convention
		// ParkOrbit/CallPickup follow at their own answer time.
		newSession->setLocalTag(toTag);
		newSession->setDialogHeaders(std::string(data->getFrom()),
			std::string(data->getTo()) + ";tag=" + toTag);
		ringing->setTo(std::string(data->getTo()) + ";tag=" + toTag);
		ringing->setContact(buildContact("777"));
		_outbox.emplace_back(data->getSource(), std::move(ringing));

		okResponse->setHeader(SipMessageTypes::OK);
		okResponse->setVia(sipwire::viaWithReceived(data->getVia(), data->getSource()));
		okResponse->setTo(std::string(data->getTo()) + ";tag=" + toTag);
		okResponse->setContact(buildContact("777"));
		// The echo answer is the CALLER'S OWN offer handed back, so it must obey
		// RFC 3264 §6.1: an answer reuses the offer's payload-type numbers and may
		// only narrow the list. enforceG711() pinned the m= line to a literal
		// "0 8 101" instead — inventing PT 101 with no a=rtpmap for it (invalid per
		// RFC 4566 §6 for a dynamic PT) and asserting PTs the offer may never have
		// used. pjsip rejects that answer outright ("Missing SDP rtpmap for dynamic
		// payload type") and the echo call dies. filterAudioCodecs keeps the
		// caller's own numbering, order and rtpmap/fmtp lines, dropping only what
		// this leg cannot carry; the 488 gate above guarantees something survives.
		// Issue #304: allowPcma=false here too -- the gate above only refuses a
		// PCMA-ONLY offer; a dual-codec PCMU+PCMA offer passes it fine, and
		// without this the echoed answer would still list PT8, leaving the peer
		// free to pick it and send audio nothing on this leg can decode.
		okResponse->filterAudioCodecs(/*allowWideband=*/false, /*allowPcma=*/false);
		_outbox.emplace_back(data->getSource(), std::move(okResponse));
		return;
	}

	if (destNumber == "999")
	{
		// All Page / Broadcast: fork to every other registered client, with the
		// intercom auto-answer headers. Targets are picked here; the fork machinery
		// is the shared startBroadcastFork() helper (also used by ring groups).
		std::vector<std::shared_ptr<SipClient>> targets;
		for (const auto& client : _clientPool)
		{
			if (!client->getNumber().empty() && client->getNumber() != caller.value()->getNumber())
			{
				targets.push_back(client);
			}
		}

		if (targets.empty())
		{
			std::shared_ptr<SipMessage> responseObj = getMessageFromPool(*data);
			if (!responseObj) return;   // pool exhausted: drop, peer retransmits (#101A)
			responseObj->setHeader(SipMessageTypes::NOT_FOUND);
			responseObj->clearBody();
			responseObj->setContact(buildContact(caller.value()->getNumber()));
			_outbox.emplace_back(data->getSource(), std::move(responseObj));
			return;
		}

		_forker.startBroadcastFork(data, caller.value(), std::move(targets), /*intercom=*/true);
		return;
	}

	// Paging zones (980–989): a configured zone is a scoped 999 — fork an intercom
	// INVITE to every registered zone member. An unconfigured 98x falls through to
	// normal routing (and 404s, since 98x is not a real extension/group target).
	if (pbx::isPageZoneExt(destNumber))
	{
		if (const pbx::PageZone* zone = _cfg.findPageZone(destNumber))
		{
			_forker.routePageZone(data, caller.value(), *zone);
			return;
		}
	}

	if (destNumber == "440")
	{
		// Media beachhead: the server answers and sources a one-way RTP tone stream.
		onMediaInvite(data, caller.value());
		return;
	}

	if (destNumber == ConferenceRoom::EXT)
	{
		// Meet-me conference (888): the server answers, joins this caller to the one
		// shared MixBus, and mixes. N callers dialing 888 are N legs of one conference.
		onConferenceInvite(data, caller.value());
		return;
	}

	if (destNumber == kAnchorCallExt)
	{
		// Anchored media (555): the server answers and bridges this caller's RTP to
		// whatever AnchorClient the boot-time provider registry selected.
		onAnchorInvite(data, caller.value());
		return;
	}

	if (destNumber == kVoicemailRetrievalExt)
	{
		// Voicemail retrieval dial-in (796, Issue #246): the server answers
		// and streams the CALLER'S OWN mailbox back -- see
		// answerVoicemailRetrieval()'s doc comment for the no-PIN MVP
		// tradeoff and why this is a fresh-dial dispatch, unlike
		// answerVoicemailDeposit()'s mid-call-fallback shape.
		answerVoicemailRetrieval(data, caller.value());
		return;
	}

	// Call parking (park-orbit, 700..70N): an INVITE to a FREE orbit parks the
	// caller's leg there; an INVITE to an OCCUPIED orbit retrieves the parked call.
	{
		int orbitIdx = _park.orbitIndex(destNumber);
		if (orbitIdx >= 0)
		{
			_park.onInvite(data, caller.value(), orbitIdx);
			return;
		}
	}

	// Directed / group call pickup (Issue #68): *8 answers the oldest ringing
	// call among the picker's ring-group co-members; **<ext> answers a named
	// extension's ringing call. Both are restricted to the picker's own
	// pickup group (same ring-group co-membership check) — see
	// PbxConfig.hpp's doc comment for why directed pickup isn't exempted.
	if (pbx::isGroupPickupCode(destNumber))
	{
		auto candidates = _cfg.pickupPeersOf(caller.value()->getNumber());
		std::string ringingCallId, ringingExt;
		auto ringing = candidates.empty() ? nullptr
			: findRingingSessionAmong(candidates, ringingCallId, ringingExt);
		_pickup.complete(data, caller.value(), ringing, ringingCallId, ringingExt);
		return;
	}
	if (std::string target = pbx::directedPickupTarget(destNumber); !target.empty())
	{
		auto peers = _cfg.pickupPeersOf(caller.value()->getNumber());
		bool eligible = target != caller.value()->getNumber() &&
			std::find(peers.begin(), peers.end(), target) != peers.end();
		std::vector<std::string> candidates = eligible ? std::vector<std::string>{ target } : std::vector<std::string>{};
		std::string ringingCallId, ringingExt;
		auto ringing = candidates.empty() ? nullptr
			: findRingingSessionAmong(candidates, ringingCallId, ringingExt);
		_pickup.complete(data, caller.value(), ringing, ringingCallId, ringingExt);
		return;
	}

	// Ring / hunt groups (Class A sweep): a configured group extension (e.g. 6xx)
	// maps to an ordered member list. Ring-all reuses the broadcast fork (without the
	// intercom auto-answer headers, so members ring normally); hunt rings members one
	// at a time, driven from tick(). Resolved before DND because a group ext is not a
	// real endpoint and so never carries its own DND/forward config.
	if (const pbx::RingGroup* group = _cfg.findRingGroup(destNumber))
	{
		_forker.routeRingGroup(data, caller.value(), destNumber, *group);
		return;
	}

	// Dial plan (Issue #69): the bounded, ordered pattern → action rule table.
	// Deliberately evaluated HERE — after every reserved virtual extension (777,
	// 999, 98x zones, 440, 70x orbits) and after the direct ring-group lookup, but
	// before CFU/DND/extension lookup. That ordering is what makes the feature
	// additive rather than a behavior change: a rule can only ever intercept a
	// dialed number that would otherwise have reached the ordinary extension
	// lookup (and, for an unknown number, 404). No rule can shadow the echo test,
	// a park retrieval or a configured group extension — so even a catch-all "*"
	// pattern leaves the built-ins working. Nothing matched ⇒ routeDialPlan()
	// returns false and everything below runs exactly as it did before #69.
	if (_forker.routeDialPlan(data, caller.value(), destNumber))
	{
		return;
	}

	// Call Forward Unconditional (CFU): if the destination has an "always" forward
	// target, redirect the call to that target before ringing the original callee.
	{
		std::string cfu = _cfg.getForwardTarget(destNumber, "always");
		if (!cfu.empty() && cfu != destNumber)
		{
			queueLog("CFU: forwarding " + destNumber + " -> " + cfu);
			if (_forker.redirectInvite(data, caller.value(), cfu))
			{
				return;
			}
			// Forward target offline: fall through and try the original callee.
		}
	}

	// Do Not Disturb (Phase 2): if the target extension has DND enabled, decline
	// with 480 Temporarily Unavailable instead of ringing it. This branch is reached
	// only for ordinary extensions — the virtual 777 (echo) and 999 (broadcast)
	// extensions are handled above and so are never affected by DND.
	if (_cfg.isDndEnabled(destNumber))
	{
		auto response = getMessageFromPool(*data);
		if (!response) return;   // pool exhausted: drop, peer retransmits (#101A)
		response->setHeader("SIP/2.0 480 Temporarily Unavailable");
		response->clearBody();
		response->setVia(sipwire::viaWithReceived(data->getVia(), data->getSource()));
		response->setContact(buildContact(caller.value()->getNumber()));
		endHandle(data->getFromNumber(), response);
		return;
	}

	// Check if the called is registered
	auto called = findClient(data->getToNumber());
	if (!called.has_value())
	{
		// Send "SIP/2.0 404 Not Found"
		std::shared_ptr<SipMessage> responseObj = getMessageFromPool(*data);
		if (!responseObj) return;   // pool exhausted: drop, peer retransmits (#101A)
		responseObj->setHeader(SipMessageTypes::NOT_FOUND);
		responseObj->clearBody();
		responseObj->setContact(buildContact(caller.value()->getNumber()));
		endHandle(data->getFromNumber(), responseObj);
		return;
	}

	SipSdpMessage* message = nullptr;
	if (data && data->hasSdp())
	{
		message = static_cast<SipSdpMessage*>(data.get());
	}
	if (!message) 
	{
		queueLog("Couldn't get SDP from " + std::string(data->getFromNumber()) + "'s INVITE request.", true);
		std::shared_ptr<SipMessage> responseObj = getMessageFromPool(*data);
		if (!responseObj) return;   // pool exhausted: drop, peer retransmits (#101A)
		responseObj->setHeader(SipMessageTypes::BAD_REQUEST);
		responseObj->clearBody();
		responseObj->setContact(buildContact(caller.value()->getNumber()));
		endHandle(data->getFromNumber(), responseObj);
		return;
	}

	auto newSession = allocateSession(std::string(data->getCallID()), caller.value());
	if (!newSession)
	{
		std::shared_ptr<SipMessage> responseObj = getMessageFromPool(*data);
		if (!responseObj) return;   // pool exhausted: drop, peer retransmits (#101A)
		responseObj->setHeader("SIP/2.0 503 Service Unavailable");
		responseObj->clearBody();
		responseObj->setContact(buildContact(caller.value()->getNumber()));
		endHandle(data->getFromNumber(), responseObj);
		return;
	}
	_sessions.emplace(data->getCallID(), newSession);

	// Retain the original INVITE on every direct-call session — not only when
	// the callee has a conditional forward (busy/no-answer) configured.
	// onBusy()/tick() already relied on this for CFB/CFNA; it's now also how
	// isSessionRingingExt() finds "who's ringing" for call pickup (Issue #68)
	// without needing to pre-populate Session::dest before an answer exists.
	newSession->setInviteMessage(data);
	std::string cfna = _cfg.getForwardTarget(destNumber, "noanswer");
	if (!cfna.empty() && cfna != destNumber)
	{
		newSession->setNoAnswerTarget(cfna);
		newSession->armRingTimer(std::chrono::steady_clock::now() + pbx::kNoAnswerTimeout);
	}
	// Issue #246: no explicit CFNA target, but this extension has voicemail
	// enabled -- arm the timer anyway with the voicemail sentinel, decided
	// once here rather than re-checked at sweep time (see the sentinel's
	// own doc comment for why that would be a TOCTOU).
	else if (cfna.empty() && _cfg.isVoicemailEnabled(destNumber))
	{
		newSession->setNoAnswerTarget(pbx::kVoicemailForwardSentinel);
		newSession->armRingTimer(std::chrono::steady_clock::now() + pbx::kNoAnswerTimeout);
	}

	auto response = getMessageFromPool(*data);
	if (!response) return;   // pool exhausted: drop, peer retransmits (#101A)
	response->setContact(buildContact(caller.value()->getNumber()));
	endHandle(data->getToNumber(), response);
}

std::string RequestsHandler::buildMediaSdp(const std::string& serverIp, int rtpPort, bool sendrecv, int dtmfPt)
{
	// The server's OWN SDP offer/answer for a server-media call. PCMU (PT 0) only —
	// matches enforceG711()/the codec the rest of the PBX speaks. Sendonly (the 440
	// tone default): the server streams to the caller and ignores any media the caller
	// sends back. Sendrecv is what a conference leg (888) needs — the mix is only a
	// mix if the phone actually sends its own audio up.
	// CRLF line endings throughout so Content-Length (computed by the caller via
	// syncContentLength()) matches the wire bytes exactly.
	// dtmfPt: the caller's RFC 4733 telephone-event payload type, echoed back so
	// DTMF reaches us on this leg. It MUST be the number the offer used -- RFC 3264
	// forbids answering with a payload type the offer did not contain, and the PT
	// is dynamic, so there is nothing to hardcode. -1 means the offer carried none
	// (or we are building an offer of our own), in which case the answer stays
	// PCMU-only exactly as before.
	//
	// Without this the board advertised "RTP/AVP 0" and nothing else, so a
	// conformant phone had no negotiated way to send DTMF into a server-terminated
	// call at all -- and since an ordinary call's media is peer-to-peer, the RTP
	// path was the ONLY way it could have arrived. That is why a menu on 440/555/888
	// could never be driven from a handset in its default DTMF mode.
	const bool withDtmf = (dtmfPt >= 0 && dtmfPt <= 127 && dtmfPt != 0);

	std::string s;
	s += "v=0\r\n";
	s += "o=- 0 0 IN IP4 " + serverIp + "\r\n";
	s += "s=pocketdial-media\r\n";
	s += "c=IN IP4 " + serverIp + "\r\n";
	s += "t=0 0\r\n";
	s += "m=audio " + std::to_string(rtpPort) + " RTP/AVP 0";
	if (withDtmf) s += " " + std::to_string(dtmfPt);
	s += "\r\n";
	s += "a=rtpmap:0 PCMU/8000\r\n";
	if (withDtmf)
	{
		s += "a=rtpmap:" + std::to_string(dtmfPt) + " telephone-event/8000\r\n";
		// 0-15 is the DTMF subset: the sixteen keypad symbols and nothing else.
		// We deliberately do not claim 16 (hook flash) or the tone events -- the
		// receiver maps only 0-15 to a key and would drop the rest anyway.
		s += "a=fmtp:" + std::to_string(dtmfPt) + " 0-15\r\n";
	}
	s += sendrecv ? "a=sendrecv\r\n" : "a=sendonly\r\n";
	return s;
}

bool RequestsHandler::parseCallerRtp(const std::shared_ptr<SipMessage>& invite,
	std::string& outIp, uint16_t& outPort)
{
	// Explicit section selection (#253): getRtpPort()/getConnectionInformation()
	// with no argument each answer "which section?" a different, disagreeing way
	// on a multi-section body -- this PBX has never yet seen one, but that is a
	// trap waiting for the first audio+video offer, not a guarantee. Name the
	// section instead: the first "audio" m= line, the only thing a caller here
	// could mean.
	SipSdpMessage* sdp = (invite && invite->hasSdp())
		? static_cast<SipSdpMessage*>(invite.get()) : nullptr;
	const int section = sdp ? sdp->firstAudioSection() : -1;

	// Port: the m=audio port from the caller's offered SDP (0 if absent/invalid).
	int port = (section >= 0) ? sdp->getRtpPort(section) : 0;
	if (port <= 0 || port > 65535)
	{
		return false;
	}
	outPort = static_cast<uint16_t>(port);

	// IP: prefer the SDP c= line ("c=IN IP4 <addr>"); fall back to the INVITE source
	// IP (handles phones that put 0.0.0.0 or a private/NAT addr in c=).
	outIp.clear();
	if (section >= 0)
	{
		std::string_view c = sdp->getConnectionInformation(section);   // "c=IN IP4 1.2.3.4"
		size_t ip4 = c.find("IP4 ");
		if (ip4 != std::string_view::npos)
		{
			size_t start = ip4 + 4;
			while (start < c.size() && std::isspace(static_cast<unsigned char>(c[start]))) ++start;
			size_t end = start;
			while (end < c.size() && (std::isdigit(static_cast<unsigned char>(c[end])) || c[end] == '.')) ++end;
			std::string candidate(c.substr(start, end - start));
			if (!candidate.empty() && candidate != "0.0.0.0")
			{
				outIp = candidate;
			}
		}
	}
	if (outIp.empty() && invite)
	{
		char ipBuf[INET_ADDRSTRLEN]{};
		sockaddr_in src = invite->getSource();
		inet_ntop(AF_INET, &src.sin_addr, ipBuf, sizeof(ipBuf));
		outIp = ipBuf;
	}
	return !outIp.empty();
}

void RequestsHandler::onMediaInvite(std::shared_ptr<SipMessage> data,
	const std::shared_ptr<SipClient>& caller)
{
	std::string activeIp = _localIp;

	// Issue #304: 440's tone is synthesized and G.711 µ-law encoded only
	// (RtpSender hardcodes PCMU; see RtpSender.hpp) and the answer below
	// (buildMediaSdp) is PCMU-only regardless of what was offered. A
	// PCMA-only caller could never hear the tone and could never have been
	// legally answered anyway (the answer would name a payload type it
	// never offered) -- refuse before the single-stream slot is claimed.
	if (data->hasSdp() && !data->offersSupportedAudio(/*allowWideband=*/false, /*allowPcma=*/false))
	{
		auto notAcceptable = getMessageFromPool(*data);
		if (!notAcceptable) return;   // pool exhausted: drop, peer retransmits (#101A)
		notAcceptable->setHeader("SIP/2.0 488 Not Acceptable Here");
		notAcceptable->clearBody();
		notAcceptable->setVia(sipwire::viaWithReceived(data->getVia(), data->getSource()));
		notAcceptable->setContact(buildContact("440"));
		_outbox.emplace_back(data->getSource(), std::move(notAcceptable));
		queueLog("440 media: no G.711 codec offered, rejected " + std::string(data->getFromNumber()), true);
		return;
	}

	// Single-stream cap: a 2nd dial of 440 while a stream is live is rejected so the
	// one media slot/socket/task is never double-booked (degrade gracefully).
	if (_rtpSender.isActive())
	{
		auto busy = getMessageFromPool(*data);
		if (!busy) return;   // pool exhausted: drop, peer retransmits (#101A)
		busy->setHeader("SIP/2.0 486 Busy Here");
		busy->clearBody();
		busy->setVia(sipwire::viaWithReceived(data->getVia(), data->getSource()));
		busy->setContact(buildContact("440"));
		_outbox.emplace_back(data->getSource(), std::move(busy));
		queueLog("440 media: busy (one stream max), rejected " + std::string(data->getFromNumber()));
		return;
	}

	// Resolve where to stream: caller's RTP addr:port (c= line + m= port, src fallback).
	std::string destIp;
	uint16_t destPort = 0;
	if (!parseCallerRtp(data, destIp, destPort))
	{
		auto bad = getMessageFromPool(*data);
		if (!bad) return;   // pool exhausted: drop, peer retransmits (#101A)
		bad->setHeader(SipMessageTypes::BAD_REQUEST);
		bad->clearBody();
		bad->setVia(sipwire::viaWithReceived(data->getVia(), data->getSource()));
		bad->setContact(buildContact("440"));
		_outbox.emplace_back(data->getSource(), std::move(bad));
		queueLog("440 media: no usable RTP destination in INVITE from "
			+ std::string(data->getFromNumber()), true);
		return;
	}

	// Start the RTP tone stream FIRST. Sending 200 OK before the stream is up risks
	// answering the call (caller hears nothing) when the socket/task fails to start,
	// recoverable only by the caller hanging up. On failure answer 500 instead.
	if (!_rtpSender.start(destIp, destPort, std::string(data->getCallID())))
	{
		auto err = getMessageFromPool(*data);
		if (!err) return;   // pool exhausted: drop, peer retransmits (#101A)
		err->setHeader("SIP/2.0 500 Server Internal Error");
		err->clearBody();
		err->setVia(sipwire::viaWithReceived(data->getVia(), data->getSource()));
		err->setContact(buildContact("440"));
		_outbox.emplace_back(data->getSource(), std::move(err));
		queueLog("440 media: RTP stream failed to start to " + destIp + ":"
			+ std::to_string(destPort), true);
		return;
	}

	// Track a Session so the dashboard shows the call and CDR is recorded on teardown.
	// If the session pool is full, stop the stream we just started and answer 503
	// rather than streaming an untracked call that nothing can later tear down.
	// (Its per-session dummy dest — never a shared client, so a concurrent 777/440
	// can't overwrite this call's destination identity — is drawn below, once this
	// session is in hand.)
	auto newSession = allocateSession(std::string(data->getCallID()), caller);
	if (!newSession)
	{
		_rtpSender.stop(std::string(data->getCallID()));
		auto busy = getMessageFromPool(*data);
		if (!busy) return;   // pool exhausted: drop, peer retransmits (#101A)
		busy->setHeader("SIP/2.0 503 Service Unavailable");
		busy->clearBody();
		busy->setVia(sipwire::viaWithReceived(data->getVia(), data->getSource()));
		busy->setContact(buildContact("440"));
		_outbox.emplace_back(data->getSource(), std::move(busy));
		queueLog("440 media: session pool full, rejected " + std::string(data->getFromNumber()), true);
		return;
	}

	// The per-session dummy dest, drawn from _virtualPeerPool instead of
	// make_shared'd in the packet handler (drawbridge audit #70 — invariant 1,
	// zero heap allocation in the packet hot path; PoolConfig.hpp:121-126 has
	// listed the 440 media beachhead as pool-drawn all along).
	//
	// Deliberately AFTER allocateSession(): it used to be built first, so a call
	// that then hit the session-pool-full 503 above had already churned a peer
	// slot for a session that never existed. The pool is sized
	// POCKETDIAL_MAX_SESSIONS + POCKETDIAL_PARK_SLOTS, so with the session in
	// hand this should never fail — but pocket-dial's allocator returns nullptr
	// past POCKETDIAL_VPEER_HEAP_FALLBACK_MAX (drawbridge's always heap-falls
	// back), and setDest(nullptr) would publish a Connected session whose
	// teardown/CDR paths dereference getDest(). Unwind the RTP stream and answer
	// 503, exactly as the session-pool-full branch directly above does.
	auto dummy440 = allocateVirtualPeer("440", data->getSource());
	if (!dummy440)
	{
		_rtpSender.stop(std::string(data->getCallID()));
		auto busy = getMessageFromPool(*data);
		if (!busy) return;   // pool exhausted: drop, peer retransmits (#101A)
		busy->setHeader("SIP/2.0 503 Service Unavailable");
		busy->clearBody();
		busy->setVia(sipwire::viaWithReceived(data->getVia(), data->getSource()));
		busy->setContact(buildContact("440"));
		_outbox.emplace_back(data->getSource(), std::move(busy));
		queueLog("440 media: virtual-peer pool exhausted, stream unwound, rejected "
			+ std::string(data->getFromNumber()), true);
		return;
	}

	// The 200 OK is drawn BEFORE the session is published, because past
	// _sessions.emplace() + Connected there is no clean way back: the caller's
	// INVITE retransmit would hit the _rtpSender.isActive() guard at the top of
	// this function and be answered 486 Busy Here, with the tone still streaming
	// to a peer that never got an answer. Unwinding the stream here — the same
	// thing the session-pool-full path above does — leaves the retransmit a clean
	// retry (#101A).
	auto ok = getMessageFromPool(*data);
	if (!ok)
	{
		_rtpSender.stop(std::string(data->getCallID()));
		queueLog("440 media: message pool exhausted, stream unwound", true);
		return;
	}

	newSession->setDest(dummy440);
	_sessions.emplace(data->getCallID(), newSession);
	newSession->setState(Session::State::Connected);

	// Build the 200 OK carrying the SERVER's own SDP. We rebuild the message body
	// directly (there is no generic body setter): take the INVITE clone, strip its
	// body, then append our SDP and the SDP Content-Type, and resync Content-Length
	// via enforceG711()/syncContentLength() so the answer isn't dropped on UDP (the
	// 777-bug class — see tests/SipMessage_test.cpp).
	std::string toTag = IDGen::GenerateID(9);
	std::string sdpBody = buildMediaSdp(activeIp, _rtpSender.serverRtpPort());

	// Assemble the OK from the INVITE's headers + our body. clearBody() leaves the
	// header/blank-line boundary intact; we then append Content-Type + the SDP and
	// let syncContentLength() (invoked by enforceG711) fix the length.
	ok->setHeader(SipMessageTypes::OK);
	ok->setVia(sipwire::viaWithReceived(data->getVia(), data->getSource()));
	ok->setTo(std::string(data->getTo()) + ";tag=" + toTag);
	ok->setContact(buildContact("440"));
	ok->clearBody();
	// Append our SDP body after the header/body separator. We rebuild the raw string
	// because clearBody() emptied the body and zeroed length. The cloned INVITE
	// already carries "Content-Type: application/sdp" (which clearBody() does NOT
	// strip), so only add the header if it is somehow absent — never duplicate it.
	{
		std::string raw = ok->toString();
		size_t sep = raw.find("\r\n\r\n");
		if (sep != std::string::npos)
		{
			std::string_view headerView(raw.data(), sep);
			if (headerView.find("application/sdp") == std::string_view::npos)
			{
				// No SDP Content-Type yet: splice one in just before the blank line.
				raw.insert(sep, "\r\nContent-Type: application/sdp");
				sep = raw.find("\r\n\r\n");   // separator moved by the inserted bytes
			}
			raw.erase(sep + 4);          // drop anything stale after the separator
			raw += sdpBody;              // append our SDP body
		}
		ok->reset(std::move(raw), data->getSource());
	}
	// No enforceG711() here: sdpBody is buildMediaSdp()'s own body, already exactly
	// "m=audio N RTP/AVP 0" + a=rtpmap:0 PCMU/8000. enforceG711() did not "collapse"
	// that list, it WIDENED it to "0 8 101" -- adding a dynamic PT 101 with no
	// a=rtpmap line, which RFC 4566 forbids and pjsip rejects with 400 Bad SDP.
	ok->syncContentLength();             // length == body bytes
	_outbox.emplace_back(data->getSource(), std::move(ok));

	queueLog("440 media: streaming tone to " + destIp + ":" + std::to_string(destPort)
		+ " (callID=" + std::string(data->getCallID()) + ")");
}

// ── Local N-way conference (virtual extension 888) ───────────────────────────
// Issue #75 / docs/CONFERENCE_MIXER.md §7. Every caller that dials 888 gets its own
// leg on ONE shared ConferenceRoom: a MediaBridge in BUS mode, its own RTP receive
// port, and one MixBus port. The bus's single tick then hands each leg the saturated
// sum of the OTHER legs, so a third caller joining is just a third port — no signaling
// fan-out, no per-pair wiring, and a leg leaving only marks its port Draining.
//
// Ordering discipline is copied deliberately from onMediaInvite() above (Issue #115):
// parse the caller's RTP -> join the room -> allocate the session -> draw the 200 OK
// from the message pool -> only THEN publish the session and answer. Every failure
// before the answer unwinds what it started, so the caller's INVITE retransmit finds
// a clean slate instead of a half-joined leg with no dialog behind it.
void RequestsHandler::onConferenceInvite(std::shared_ptr<SipMessage> data,
	const std::shared_ptr<SipClient>& caller)
{
	const std::string activeIp = _localIp;
	const std::string callID(data->getCallID());
	const std::string confExt(ConferenceRoom::EXT);

	auto refuse = [&](const char* statusLine, const char* why) {
		auto msg = getMessageFromPool(*data);
		if (!msg) return;   // pool exhausted: drop, peer retransmits (#101A)
		msg->setHeader(statusLine);
		msg->clearBody();
		msg->setVia(sipwire::viaWithReceived(data->getVia(), data->getSource()));
		msg->setContact(buildContact(confExt));
		_outbox.emplace_back(data->getSource(), std::move(msg));
		queueLog("888 conference: " + std::string(why) + " for "
			+ std::string(data->getFromNumber()), true);
	};

	// Issue #304: conference mixing only understands PCMU -- RtpReceiver.cpp
	// only recognizes PAYLOAD_TYPE_PCMU as audio; anything else (PCMA
	// included) falls through to the DTMF-event check and is dropped. Same
	// reasoning as the 777/anchor gates: refuse a PCMA-only offer rather
	// than mix silence in from this leg.
	if (data->hasSdp() && !data->offersSupportedAudio(/*allowWideband=*/false, /*allowPcma=*/false))
	{
		refuse("SIP/2.0 488 Not Acceptable Here", "no G.711 codec offered");
		return;
	}

	// Where does this phone want its audio? Same c=/m= parse the 440 path uses.
	std::string destIp;
	uint16_t destPort = 0;
	if (!parseCallerRtp(data, destIp, destPort))
	{
		refuse(SipMessageTypes::BAD_REQUEST, "no usable RTP destination in INVITE");
		return;
	}

	// The room (and its single mix-tick driver) is built on the first dial-in and then
	// kept for the life of the process: standing the tick task up and down underneath
	// legs whose RTP tasks may still be in flight is exactly the teardown race the bus's
	// Draining state exists to avoid. Idle cost is the bus rings; see PoolConfig.hpp.
	if (!_conference)
	{
		_conference = std::make_unique<ConferenceRoom>();
		// Issue #199 item 3: give every leg a way to hand an RFC 4733 key press
		// back to the engine. Invoked on that leg's RTP receive task, so it goes
		// to queueDtmfDigit(), which is the one entry point here built to be
		// called without _mutex held.
		_conference->setDigitSink([this](std::string_view legCallId, char digit) {
			queueDtmfDigit(legCallId, digit);
		});
		_conference->startDriver();
		queueLog("888 conference: room created (" + std::to_string(ConferenceRoom::MAX_LEGS)
			+ " legs, " + std::to_string(ConferenceRoom::TICK_MS) + " ms mix tick)");
	}

	// Join first: a full room must not consume a session slot. The leg index is also
	// the proof the media actually came up, so nothing is answered on a dead leg.
	const int leg = _conference->join(callID, std::string(caller->getNumber()), destIp, destPort,
		data->getTelephoneEventPayloadType());
	if (leg < 0)
	{
		refuse("SIP/2.0 486 Busy Here", "room full or media failed to start");
		return;
	}

	auto newSession = allocateSession(callID, caller);
	if (!newSession)
	{
		_conference->leave(callID);
		refuse("SIP/2.0 503 Service Unavailable", "session pool full");
		return;
	}

	// Draw the answer BEFORE publishing the session — past _sessions.emplace() the
	// retransmission guard at the top of onInvite() silently drops the caller's retry,
	// so a pool refusal here would strand a joined leg with no answer ever sent.
	// The SDP advertises THIS LEG's receive port (not the 440 sender's port): that is
	// where the handset must send its audio for the mix to hear it.
	const std::string toTag = IDGen::GenerateID(9);
	// Echo the caller's telephone-event PT (RFC 4733) so keypresses reach the mix
	// leg. A conference is exactly the place this matters -- PIN entry and in-call
	// controls are keypresses on a leg the server terminates, and before this the
	// answer advertised PCMU alone so a phone had no negotiated way to send them.
	const std::string sdpBody = buildMediaSdp(activeIp, _conference->rtpPortFor(callID),
		/*sendrecv=*/true, data->getTelephoneEventPayloadType());
	auto ok = buildOkWithSdp(data, activeIp, toTag, sdpBody);
	if (!ok)
	{
		_conference->leave(callID);
		queueLog("888 conference: message pool exhausted, leg unwound", true);
		return;
	}

	// Per-session dummy dest (never a shared client) so a concurrent 777/440/888 call
	// can't overwrite this call's destination identity.
	auto dummyConf = allocateVirtualPeer(confExt, data->getSource());
	newSession->setDest(dummyConf);
	// Issue #232: same reasoning as the 777 echo leg (RequestsHandler.cpp,
	// onInvite's "777" branch) — record this leg's own To-tag now, since
	// nothing else ever will, or forceDisconnect()'s #72 guard can never BYE
	// this handset later.
	newSession->setLocalTag(toTag);
	newSession->setDialogHeaders(std::string(data->getFrom()),
		std::string(data->getTo()) + ";tag=" + toTag);
	_sessions.emplace(callID, newSession);
	newSession->setState(Session::State::Connected);

	_outbox.emplace_back(data->getSource(), std::move(ok));

	queueLog("888 conference: " + std::string(caller->getNumber()) + " joined leg "
		+ std::to_string(leg) + " (" + std::to_string(_conference->legCount()) + "/"
		+ std::to_string(ConferenceRoom::MAX_LEGS) + "), media to "
		+ destIp + ":" + std::to_string(destPort));
}

void RequestsHandler::loadVoicemailGreeting()
{
	constexpr const char* kGreetingPath = "/sdcard/vm/greeting.wav";

	std::FILE* f = std::fopen(kGreetingPath, "rb");
	if (f == nullptr) return;   // no greeting on the card -- stays null, graceful degradation

	std::fseek(f, 0, SEEK_END);
	const long total = std::ftell(f);
	std::fseek(f, 0, SEEK_SET);
	if (total <= 0)
	{
		std::fclose(f);
		return;
	}

	// Same header-first-then-allocate ordering as HoldMusic::loadClip() and
	// for the same reason: reject a wrong-format file without allocating
	// megabytes for it first.
	uint8_t head[1024];
	const size_t headLen = std::fread(head, 1, sizeof(head) < static_cast<size_t>(total)
	                                            ? sizeof(head) : static_cast<size_t>(total), f);
	size_t dataOff = 0, dataLen = 0;
	if (!HoldMusic::parseUlawWav(head, headLen, dataOff, dataLen))
	{
		std::fclose(f);
		queueLog("Voicemail: greeting at " + std::string(kGreetingPath) +
			" is not a valid 8kHz mono mu-law WAV -- deposits will record immediately", true);
		return;
	}
	if (dataOff + dataLen > static_cast<size_t>(total)) dataLen = static_cast<size_t>(total) - dataOff;

	// Issue #466: the same placement rule as the MoH clip -- PSRAM only where
	// the board has it, capped internal DRAM where it has none, and a refusal
	// is counted and flagged rather than silently spilling into internal RAM.
	uint8_t* buf = HoldMusic::allocClip(dataLen);
	_greetingRefused.store(buf == nullptr, std::memory_order_relaxed);
	if (buf == nullptr)
	{
		std::fclose(f);
		queueLog("[WARN] Voicemail: greeting at " + std::string(kGreetingPath) + " (" +
			std::to_string(dataLen) + " B) REFUSED -- PSRAM short, or over the " +
			std::to_string(POCKETDIAL_CLIP_INTERNAL_MAX_BYTES) +
			" B internal cap on a board without PSRAM (#466); deposits will record immediately", true);
		return;
	}

	std::fseek(f, static_cast<long>(dataOff), SEEK_SET);
	const size_t got = std::fread(buf, 1, dataLen, f);
	std::fclose(f);

	if (got == 0)
	{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
		heap_caps_free(buf);
#else
		std::free(buf);
#endif
		return;
	}

	_vmGreetingClip = buf;
	_vmGreetingClipLen = got;
	queueLog("Voicemail: greeting loaded (" + std::to_string(got) + " bytes)");
}

int RequestsHandler::findFreeVoicemailSlot() const
{
	for (size_t i = 0; i < POCKETDIAL_MAX_VOICEMAIL_LEGS; ++i)
	{
		if (!_vmRtpReceivers[i].isActive() &&
			!_vmFlushBusy[i].load(std::memory_order_acquire) &&
			_vmSdJobState[i].load(std::memory_order_acquire) == VmSdJobState::Idle)
		{
			return static_cast<int>(i);
		}
	}
	return -1;
}

void RequestsHandler::answerVoicemailDeposit(const std::shared_ptr<SipMessage>& invite,
	const std::shared_ptr<SipClient>& src, const std::string& extension)
{
	const std::string activeIp = _localIp;
	const std::string callID(invite->getCallID());

	auto refuse = [&](const char* statusLine, const char* why) {
		auto msg = getMessageFromPool(*invite);
		if (!msg) return;   // pool exhausted: drop, peer retransmits (#101A)
		msg->setHeader(statusLine);
		msg->clearBody();
		msg->setVia(sipwire::viaWithReceived(invite->getVia(), invite->getSource()));
		msg->setContact(buildContact(extension));
		_outbox.emplace_back(invite->getSource(), std::move(msg));
		queueLog("Voicemail: " + std::string(why) + " for " + std::string(src->getNumber())
			+ " -> " + extension, true);
	};

	// Issue #304: recording only understands PCMU -- onCallerRtp() below is
	// fed raw µ-law bytes by the RTP receiver, which (RtpReceiver.cpp) only
	// recognizes PAYLOAD_TYPE_PCMU as audio and silently drops anything
	// else after the DTMF-event check. A PCMA-only caller's message would
	// otherwise record as silence rather than fail loudly -- refuse here
	// instead.
	if (invite->hasSdp() && !invite->offersSupportedAudio(/*allowWideband=*/false, /*allowPcma=*/false))
	{
		refuse("SIP/2.0 488 Not Acceptable Here", "no G.711 codec offered");
		return;
	}

	// Where does the caller want its audio sent? Same c=/m= parse 440/888 use
	// against their own inbound INVITE -- here it's the RETAINED invite,
	// since this fires well after the original INVITE was received.
	std::string destIp;
	uint16_t destPort = 0;
	if (!parseCallerRtp(invite, destIp, destPort))
	{
		refuse(SipMessageTypes::BAD_REQUEST, "no usable RTP destination in retained invite");
		return;
	}

	// Find a free leg -- see findFreeVoicemailSlot()'s doc comment.
	const int slot = findFreeVoicemailSlot();
	if (slot < 0)
	{
		refuse("SIP/2.0 486 Busy Here", "every voicemail leg busy, rejected deposit");
		return;
	}
	if (_vmRecordBufs[slot] == nullptr)
	{
		// Boot-time allocation failed for this leg (see the constructor's
		// queueLog on failure) -- refuse rather than record into a null
		// pointer. Every other leg is unaffected.
		refuse("SIP/2.0 500 Server Internal Error", "voicemail leg has no recording buffer");
		return;
	}

	// Claim the leg BEFORE starting the RTP receiver, not after: onCallerRtp()
	// could otherwise fire (real hardware, receive task starts near-instantly)
	// while the leg is still Idle and silently drop the call's opening frames.
	// Play the greeting first when one is loaded (Playing -> PlaybackDone ->
	// tick()'s sweep starts recording); with no greeting, record immediately
	// -- the pre-greeting behavior, still exercised by every host test that
	// never loads one. Either call claims the leg out of Idle the same way.
	const bool claimed = (_vmGreetingClip != nullptr && _vmGreetingClipLen > 0)
		? _vmLegs[slot].startPlaying(_vmGreetingClip, _vmGreetingClipLen, extension, callID)
		: _vmLegs[slot].startRecording(_vmRecordBufs[slot], POCKETDIAL_VOICEMAIL_MAX_MESSAGE_BYTES,
			POCKETDIAL_VOICEMAIL_MAX_MESSAGE_BYTES, extension, callID);
	if (!claimed)
	{
		// Only reachable if the leg was somehow left Recording/Finalizing
		// despite _vmRtpReceivers[slot] reporting inactive -- a slot-tracking
		// bug elsewhere, not a normal refusal path. Refuse rather than record
		// over a not-yet-flushed message.
		refuse("SIP/2.0 500 Server Internal Error", "voicemail leg claim failed");
		return;
	}

	// Pass localPort 0 so the OS picks an ephemeral port on real hardware
	// (read back via localPort() below), exactly like MediaBridge::startBridge()
	// does for the anchor pool -- 0 stays 0 on host, same as every other
	// caller of this pattern.
	const bool rxStarted = _vmRtpReceivers[slot].start(0,
		[this, slot](const uint8_t* mulaw, size_t n, uint32_t /*timestamp*/, uint16_t /*seq*/) {
			_vmLegs[slot].onCallerRtp(mulaw, n);
		});
	if (!rxStarted)
	{
		_vmLegs[slot].reset();
		refuse("SIP/2.0 500 Server Internal Error", "voicemail RTP receiver failed to start");
		return;
	}
	if (!_vmRtpSenders[slot].start(destIp, destPort, callID,
		[this, slot](uint8_t* outUlaw, size_t count) {
			return _vmLegs[slot].fillTx(outUlaw, count);
		}))
	{
		_vmRtpReceivers[slot].stop();
		_vmLegs[slot].reset();
		refuse("SIP/2.0 500 Server Internal Error", "voicemail RTP sender failed to start");
		return;
	}

	auto newSession = allocateSession(callID, src);
	if (!newSession)
	{
		_vmRtpReceivers[slot].stop();
		_vmRtpSenders[slot].stop(callID);
		_vmLegs[slot].reset();
		refuse("SIP/2.0 503 Service Unavailable", "session pool full, rejected deposit");
		return;
	}

	const std::string toTag = IDGen::GenerateID(9);
	// buildMediaSdp() still answers sendrecv unconditionally (not offer-aware)
	// -- matches every OTHER locally-terminated leg today (777/888/anchor)
	// until #196 Phase 2's SDP model replacement lands; tracked as a
	// follow-up for this leg too, not a regression introduced here.
	const std::string sdpBody = buildMediaSdp(activeIp, _vmRtpReceivers[slot].localPort(),
		/*sendrecv=*/true, invite->getTelephoneEventPayloadType());
	auto ok = buildOkWithSdp(invite, activeIp, toTag, sdpBody);
	if (!ok)
	{
		_vmRtpReceivers[slot].stop();
		_vmRtpSenders[slot].stop(callID);
		_vmLegs[slot].reset();
		queueLog("Voicemail: message pool exhausted answering " + extension, true);
		return;
	}

	// Per-session dummy dest, drawn from the virtual peer pool like every
	// other locally-terminated leg (777/888/anchor) -- never a shared
	// client, so a concurrent voicemail call can't overwrite this one's
	// destination identity.
	//
	// Noted, not fixed here (found in review): forceDisconnect() BYEs both
	// legs of a session, so an admin-killed voicemail call will emit a BYE
	// toward this dummy "700" address -- the same #232 shape 777/888 already
	// have (a locally-terminated leg's dummy dest isn't a real phone to BYE).
	// Whoever picks up #232 broadly should include this leg.
	auto dummyVm = allocateVirtualPeer("700", invite->getSource());
	newSession->setDest(dummyVm);
	newSession->setVoicemail(true);
	newSession->setVoicemailLegSlot(slot);
	newSession->setVoicemailPurpose(Session::VoicemailPurpose::Deposit);
	// Wall-clock safety net (see the class comment on armVoicemailDeadline()):
	// covers the whole call, greeting included, not just the Recording phase
	// -- a greeting that somehow never reaches PlaybackDone (a corrupt clip
	// with a length that never lets the cursor catch up, say) must not pin
	// this leg forever either.
	newSession->armVoicemailDeadline(std::chrono::steady_clock::now() +
		std::chrono::seconds(POCKETDIAL_VOICEMAIL_MAX_MESSAGE_SECONDS));
	_sessions.emplace(callID, newSession);
	newSession->setState(Session::State::Connected);

	// Issue #232 (777/888 legs never get a BYE matched correctly): capture
	// BOTH sides' dialog identity HERE, directly, the way ParkOrbit/CallPickup
	// do -- not via armSessionTimer(), which only sets this when
	// Session-Expires was negotiated (and whose early-return guard runs
	// BEFORE its own setDialogHeaders() call despite a comment claiming
	// otherwise -- a separate, pre-existing bug, not fixed here).
	newSession->setDialogHeaders(std::string(ok->getFrom()), std::string(ok->getTo()));

	_outbox.emplace_back(invite->getSource(), std::move(ok));

	queueLog("Voicemail: " + std::string(src->getNumber()) + " -> " + extension
		+ " deposit answered locally (leg " + std::to_string(slot) + ")");
}

void RequestsHandler::enqueueVoicemailFlush(int slot)
{
	if (slot < 0 || slot >= static_cast<int>(POCKETDIAL_MAX_VOICEMAIL_LEGS)) return;
	if (_vmStagingBufs[slot] == nullptr) return;   // boot-time allocation failed for this leg

	_vmLegs[slot].stopRecording();   // no-op if not Recording (e.g. answer never completed)
	const uint8_t* data = _vmLegs[slot].recordedData();
	const size_t length = _vmLegs[slot].recordedLength();
	if (data == nullptr || length == 0) return;   // nothing said -- nothing to flush

	// Copy into THIS slot's staging buffer, not the leg's own recording
	// buffer -- see VoicemailArchive.hpp's class comment for why: this is
	// what lets releaseVoicemailLeg() reset() the leg immediately afterwards
	// without waiting for the writer task to finish reading.
	std::memcpy(_vmStagingBufs[slot], data, length);

	vmarchive::QueuedRecording rec;
	rec.stagingSlot = slot;
	std::string ext = _vmLegs[slot].extension();
	std::string callId = _vmLegs[slot].callId();
	std::strncpy(rec.extension, ext.c_str(), sizeof(rec.extension) - 1);
	std::strncpy(rec.callId, callId.c_str(), sizeof(rec.callId) - 1);
	rec.epochSeconds = timesync::epochSeconds();   // 0 if never synced -- NOT dropped, see header
	rec.sequence = ++_vmFlushSequence;
	rec.length = length;

	if (_vmFlushQueue.push(rec))
	{
		// Set ONLY on a successful push -- see _vmFlushBusy's doc comment.
		// A dropped (queue-full) message has nothing left for the writer to
		// drain, so nothing will ever clear this again if it were set here.
		_vmFlushBusy[slot].store(true, std::memory_order_release);
	}
	else
	{
		queueLog("Voicemail: flush queue full, message from " + ext + " dropped", true);
	}
}

// Issue #284: RtpReceiver::DtmfSink trampoline for a voicemail retrieval leg
// -- see VmDtmfCtx's doc comment in the header. "Deaf during I/O", not
// "newest wins" (Fable-Low review): only stores a digit while no SD job is
// in flight for this slot, so a caller who presses a key mid-fetch must
// press again once the next message actually starts -- simpler and more
// honest than remembering exactly one digit whose identity would depend on
// arrival timing.
void RequestsHandler::vmDtmfSinkTrampoline(void* ctx, char digit, uint16_t /*durationMs*/)
{
	auto* c = static_cast<VmDtmfCtx*>(ctx);
	if (c->jobState->load(std::memory_order_acquire) == VmSdJobState::Idle)
	{
		c->pendingDigit->store(digit, std::memory_order_release);
	}
}

void RequestsHandler::answerVoicemailRetrieval(const std::shared_ptr<SipMessage>& invite,
	const std::shared_ptr<SipClient>& src)
{
	const std::string activeIp = _localIp;
	const std::string callID(invite->getCallID());
	const std::string extension = src->getNumber();

	auto refuse = [&](const char* statusLine, const char* why) {
		auto msg = getMessageFromPool(*invite);
		if (!msg) return;   // pool exhausted: drop, peer retransmits (#101A)
		msg->setHeader(statusLine);
		msg->clearBody();
		msg->setVia(sipwire::viaWithReceived(invite->getVia(), invite->getSource()));
		msg->setContact(buildContact(kVoicemailRetrievalExt));
		_outbox.emplace_back(invite->getSource(), std::move(msg));
		queueLog("Voicemail retrieval: " + std::string(why) + " for " + extension, true);
	};

	// Issue #304: retrieval only ever SENDS PCMU (buildMediaSdp is PCMU-only
	// regardless of what was offered) -- a PCMA-only caller could never
	// hear their own mailbox, even though this leg discards the caller's
	// own audio entirely (see the DTMF-only sink below) and so has no
	// decode concern of its own. Same reasoning as 440's gate.
	if (invite->hasSdp() && !invite->offersSupportedAudio(/*allowWideband=*/false, /*allowPcma=*/false))
	{
		refuse("SIP/2.0 488 Not Acceptable Here", "no G.711 codec offered");
		return;
	}

	// MVP auth: no PIN -- the mailbox IS whoever's dialing in, authenticated
	// purely by Caller-ID. Accepted tradeoff, documented in
	// pocket_dial_246_voicemail.md: fine for a LAN-only extension, revisit
	// if 796 ever becomes trunk-reachable.
	if (!_cfg.isVoicemailEnabled(extension))
	{
		refuse("SIP/2.0 403 Forbidden", "voicemail not enabled");
		return;
	}

	std::string destIp;
	uint16_t destPort = 0;
	if (!parseCallerRtp(invite, destIp, destPort))
	{
		refuse(SipMessageTypes::BAD_REQUEST, "no usable RTP destination in invite");
		return;
	}

	// Same free-slot rules a deposit uses -- a slot mid-flush or mid-job is
	// exactly as unavailable to a retrieval as to a new deposit.
	const int slot = findFreeVoicemailSlot();
	if (slot < 0)
	{
		refuse("SIP/2.0 486 Busy Here", "every voicemail leg busy, rejected retrieval");
		return;
	}
	if (_vmRecordBufs[slot] == nullptr)
	{
		refuse("SIP/2.0 500 Server Internal Error", "voicemail leg has no message buffer");
		return;
	}

	const bool rxStarted = _vmRtpReceivers[slot].start(0,
		[](const uint8_t* /*mulaw*/, size_t /*n*/, uint32_t /*timestamp*/, uint16_t /*seq*/) {
			// Retrieval discards the caller's own audio entirely -- there is
			// nothing to record while a caller is listening to their own
			// mailbox. The receiver must still be started (its isActive()
			// is one of findFreeVoicemailSlot()'s busy signals) and armed
			// for DTMF below; this sink intentionally does nothing.
		});
	if (!rxStarted)
	{
		refuse("SIP/2.0 500 Server Internal Error", "voicemail RTP receiver failed to start");
		return;
	}

	// RFC 4733 only for this MVP menu -- see onInfo()'s isVoicemail() guard
	// (added alongside this slice) for why SIP INFO must never reach this
	// leg's digits into the star-code parser instead.
	//
	// Issue #284: DtmfSink is a raw function pointer + void* ctx now, so the
	// per-slot state vmDtmfSinkTrampoline() needs is reached via _vmDtmfCtx
	// rather than a [this, slot] capture -- see VmDtmfCtx's doc comment.
	_vmDtmfCtx[slot] = VmDtmfCtx{ &_vmSdJobState[slot], &_vmPendingDigit[slot] };
	_vmRtpReceivers[slot].setDtmfPayloadType(invite->getTelephoneEventPayloadType(),
		&RequestsHandler::vmDtmfSinkTrampoline, &_vmDtmfCtx[slot]);

	if (!_vmRtpSenders[slot].start(destIp, destPort, callID,
		[this, slot](uint8_t* outUlaw, size_t count) {
			return _vmLegs[slot].fillTx(outUlaw, count);
		}))
	{
		_vmRtpReceivers[slot].stop();
		refuse("SIP/2.0 500 Server Internal Error", "voicemail RTP sender failed to start");
		return;
	}

	auto newSession = allocateSession(callID, src);
	if (!newSession)
	{
		_vmRtpReceivers[slot].stop();
		_vmRtpSenders[slot].stop(callID);
		refuse("SIP/2.0 503 Service Unavailable", "session pool full, rejected retrieval");
		return;
	}

	const std::string toTag = IDGen::GenerateID(9);
	// buildMediaSdp() still answers sendrecv unconditionally -- matches
	// every other locally-terminated leg today (see answerVoicemailDeposit()'s
	// identical note on buildOkWithSdp()'s offer-awareness).
	const std::string sdpBody = buildMediaSdp(activeIp, _vmRtpReceivers[slot].localPort(),
		/*sendrecv=*/true, invite->getTelephoneEventPayloadType());
	auto ok = buildOkWithSdp(invite, activeIp, toTag, sdpBody);
	if (!ok)
	{
		_vmRtpReceivers[slot].stop();
		_vmRtpSenders[slot].stop(callID);
		queueLog("Voicemail retrieval: message pool exhausted answering " + extension, true);
		return;
	}

	// Per-session dummy dest, drawn from the virtual peer pool like every
	// other locally-terminated leg -- see answerVoicemailDeposit()'s
	// identical note on the #232 shape this shares (a dummy dest isn't a
	// real phone to BYE; out of scope here too).
	auto dummyVm = allocateVirtualPeer(kVoicemailRetrievalExt, invite->getSource());
	newSession->setDest(dummyVm);
	newSession->setVoicemail(true);
	newSession->setVoicemailLegSlot(slot);
	newSession->setVoicemailPurpose(Session::VoicemailPurpose::Retrieval);
	// Initial arm covers "answered but the list never comes back" (a stuck
	// SD-I/O task, say); handleVoicemailSdJobDone() re-arms this per
	// message once real playback starts (advisor review: per-message, not
	// once here, or a long inbox would hit this deadline mid-playback of
	// an early message).
	newSession->armVoicemailDeadline(std::chrono::steady_clock::now() +
		std::chrono::seconds(POCKETDIAL_VOICEMAIL_MAX_MESSAGE_SECONDS));
	_sessions.emplace(callID, newSession);
	newSession->setState(Session::State::Connected);
	newSession->setDialogHeaders(std::string(ok->getFrom()), std::string(ok->getTo()));

	_outbox.emplace_back(invite->getSource(), std::move(ok));

	// Kick off the mailbox listing. VoicemailLeg itself stays Idle through
	// this whole window (nothing to play/record yet) -- _vmSdJobState
	// going Pending IS the busy signal findFreeVoicemailSlot() and this
	// leg's own DTMF sink above both check; no new VoicemailLeg state was
	// needed for "answered, loading."
	VmSdJob job;
	std::strncpy(job.extension, extension.c_str(), sizeof(job.extension) - 1);
	std::strncpy(job.callId, callID.c_str(), sizeof(job.callId) - 1);
	job.listRequested = true;
	_vmSdJob[slot] = job;
	_vmSdJobState[slot].store(VmSdJobState::Pending, std::memory_order_release);

	queueLog("Voicemail retrieval: " + extension + " dialed in (leg " + std::to_string(slot) + ")");
}

void RequestsHandler::runVoicemailSdJob(int slot, vmarchive::Source& source)
{
	if (_vmSdJobState[slot].load(std::memory_order_acquire) != VmSdJobState::Pending) return;
	const VmSdJob job = _vmSdJob[slot];   // snapshot -- SIP thread won't touch this again until Idle

	// Order matters: delete-then-list-then-read (advisor review). A delete
	// never affects the list read moments later in the SAME job (the
	// tombstone is already appended by the time listMessages() runs), and
	// a fresh list is what a subsequent read's name was chosen from one
	// menu-command ago, never invalidated by this job's own delete.
	if (job.deleteName[0] != '\0')
	{
		source.markDeleted(job.extension, job.deleteName);
	}
	if (job.listRequested)
	{
		_vmMessageCounts[slot] = source.listMessages(job.extension, _vmMessageLists[slot],
			POCKETDIAL_VOICEMAIL_MAX_MESSAGES_PER_BOX);
	}
	if (job.readName[0] != '\0')
	{
		_vmReadLength[slot] = source.readMessage(job.extension, job.readName,
			_vmRecordBufs[slot], POCKETDIAL_VOICEMAIL_MAX_MESSAGE_BYTES);
	}
	else
	{
		_vmReadLength[slot] = 0;
	}

	_vmSdJobState[slot].store(VmSdJobState::Done, std::memory_order_release);
}

bool RequestsHandler::handleVoicemailSdJobDone(int slot, const std::string& callID,
	const std::shared_ptr<Session>& session)
{
	const bool wasListJob = _vmSdJob[slot].listRequested;
	const bool wasReadJob = _vmSdJob[slot].readName[0] != '\0';
	VoicemailMenu::Result r;

	if (wasListJob)
	{
		r = _vmMenus[slot].start(_vmMessageCounts[slot]);
	}
	else if (wasReadJob)
	{
		if (_vmReadLength[slot] == 0)
		{
			// The message vanished under us (card pulled, race with an
			// external delete, etc) -- treat as end-of-mailbox rather than
			// leave the caller listening to silence forever.
			r = {VoicemailMenu::Command::Hangup, -1, -1};
		}
		else if (_vmLegs[slot].startPlaying(_vmRecordBufs[slot], _vmReadLength[slot],
			_vmSdJob[slot].extension, callID))
		{
			// Playing now -- re-arm per-message (see
			// answerVoicemailRetrieval()'s doc comment) and stop here;
			// there is nothing left to dispatch this tick.
			session->armVoicemailDeadline(std::chrono::steady_clock::now() +
				std::chrono::seconds(POCKETDIAL_VOICEMAIL_MAX_MESSAGE_SECONDS));
			_vmSdJobState[slot].store(VmSdJobState::Idle, std::memory_order_release);
			return false;
		}
		else
		{
			// startPlaying() only refuses from Recording/Finalizing, which a
			// Retrieval leg should never be in -- defensive, not a normal path.
			r = {VoicemailMenu::Command::Hangup, -1, -1};
		}
	}
	else
	{
		// A delete-only job completing with nothing else to consume --
		// normally unreachable, since dispatchVoicemailMenuCommand() hangs
		// up immediately after issuing a delete-only job rather than
		// waiting for it (see that function's doc comment). Nothing to do.
		_vmSdJobState[slot].store(VmSdJobState::Idle, std::memory_order_release);
		return false;
	}

	_vmSdJobState[slot].store(VmSdJobState::Idle, std::memory_order_release);
	return dispatchVoicemailMenuCommand(slot, callID, session, r);
}

bool RequestsHandler::dispatchVoicemailMenuCommand(int slot, const std::string& callID,
	const std::shared_ptr<Session>& session, const VoicemailMenu::Result& initial)
{
	// #361: this was a tail call to itself, which the T-7 call-graph guard
	// (tests/tools/check_parser_callgraph.py, CWE-674) reports as a cycle --
	// and that guard's contract is "no cycles through project code" precisely
	// so nobody has to argue about depth bounds on a 6 KB task stack. Same
	// behaviour, expressed as a loop.
	VoicemailMenu::Result r = initial;
	while (r.command == VoicemailMenu::Command::PlayPrompt)
	{
		// No prompt asset exists in this MVP -- same graceful-degradation
		// convention the deposit-side greeting already uses when unloaded.
		// Synthesize an immediate finish and let the menu decide what's next
		// (with zero messages, always Hangup).
		//
		// This runs AT MOST ONCE, and that is a property of VoicemailMenu
		// itself rather than an argument about this loop: Command::PlayPrompt
		// is emitted by exactly one statement in the whole class -- start()
		// with messageCount == 0 (VoicemailMenu.cpp:23) -- while advance()
		// returns only Hangup or PlayMessage, and onPlaybackDone() from
		// PlayingPrompt returns Hangup and moves to Done. So onPlaybackDone()
		// cannot hand back PlayPrompt from any state, and the condition below
		// is false on the second evaluation by construction. No iteration cap:
		// it would be unreachable code guarding an invariant the type already
		// enforces.
		r = _vmMenus[slot].onPlaybackDone();
	}

	VmSdJob job;
	std::strncpy(job.extension, _vmSdJob[slot].extension, sizeof(job.extension) - 1);
	std::strncpy(job.callId, callID.c_str(), sizeof(job.callId) - 1);
	bool needsJob = false;

	// Independent of `command` (Fable-Low review): a single digit-driven
	// event (e.g. '7') can require BOTH deleting the message that was
	// playing AND fetching the next one's bytes -- or, on the last
	// message, deleting AND hanging up. Defensive bounds check: VoicemailMenu's
	// own invariants mean an out-of-range index should be unreachable.
	if (r.deleteIndex >= 0 && static_cast<size_t>(r.deleteIndex) < _vmMessageCounts[slot])
	{
		std::strncpy(job.deleteName, _vmMessageLists[slot][r.deleteIndex].name,
			sizeof(job.deleteName) - 1);
		needsJob = true;
	}

	bool hangUp = (r.command == VoicemailMenu::Command::Hangup);
	if (r.command == VoicemailMenu::Command::PlayMessage)
	{
		if (r.playIndex >= 0 && static_cast<size_t>(r.playIndex) < _vmMessageCounts[slot])
		{
			// Reset BEFORE the SD task can be asked to write
			// _vmRecordBufs[slot] again (advisor review, point 3): the leg
			// may still be Playing the OLD message if a digit interrupted
			// it mid-clip. Once state != Playing, fillTx() returns false
			// under the leg's own mutex without touching the buffer, so
			// the RTP sender thread (real on a WSL/Linux host build --
			// see the flake fix earlier on this branch) is provably done
			// reading it by the time the SD task starts writing it. This
			// does NOT depend on RtpSender::stop() blocking (it doesn't,
			// on ESP) -- only on fillTx()'s own state check.
			_vmLegs[slot].reset();
			std::strncpy(job.readName, _vmMessageLists[slot][r.playIndex].name,
				sizeof(job.readName) - 1);
			needsJob = true;
		}
		else
		{
			// Defensive only -- should be unreachable (see the comment
			// above). Treat like end-of-mailbox rather than index an
			// out-of-range slot.
			hangUp = true;
		}
	}

	if (needsJob)
	{
		_vmSdJob[slot] = job;
		_vmSdJobState[slot].store(VmSdJobState::Pending, std::memory_order_release);
	}

	// Hangup with a delete-only job just queued (no read) is safe to leave
	// running after teardown -- see this function's own doc comment.
	return hangUp;
}

void RequestsHandler::sweepVoicemailLegs(std::chrono::steady_clock::time_point now)
{
	// Orphan-job sweep (Fable-Low review, Break 2): a caller hanging up
	// mid-fetch releases the RTP pair (isActive() -> false) but
	// releaseVoicemailLeg() deliberately never touches job state -- see
	// its own doc comment. Nothing else will ever consume a Done result
	// for a slot nobody's using any more, so it must be discarded HERE,
	// by slot, not by session (there is no session left to iterate to).
	for (size_t i = 0; i < POCKETDIAL_MAX_VOICEMAIL_LEGS; ++i)
	{
		// isActive() timing differs by platform (Fable-Low review): on ESP,
		// RtpReceiver::stop() is non-blocking and returns before the
		// receive task actually exits, so isActive() can read true for a
		// tick or two after releaseVoicemailLeg() calls it -- this sweep
		// simply reclaims the slot a tick or two later on real hardware
		// than a host test shows, where stop() is a synchronous no-op and
		// isActive() flips immediately. Not a correctness gap either way,
		// just don't read a host test's immediate reclaim as the device's
		// actual timing.
		if (_vmRtpReceivers[i].isActive()) continue;   // slot is in active use, not orphaned
		if (_vmSdJobState[i].load(std::memory_order_acquire) == VmSdJobState::Done)
		{
			_vmSdJobState[i].store(VmSdJobState::Idle, std::memory_order_release);
		}
	}

	std::vector<std::string> toExpire;
	for (const auto& [callID, session] : _sessions)
	{
		if (!session->isVoicemail()) continue;
		const int slot = session->getVoicemailLegSlot();
		if (slot < 0 || slot >= static_cast<int>(POCKETDIAL_MAX_VOICEMAIL_LEGS)) continue;

		if (session->getVoicemailPurpose() == Session::VoicemailPurpose::Retrieval)
		{
			// A pending digit is checked first: onDigit()'s own resulting
			// dispatch resets the leg unconditionally before requesting a
			// new Read (see dispatchVoicemailMenuCommand()), which already
			// subsumes the natural PlaybackDone-advance path below for the
			// same tick -- so the two checks never need to both fire.
			bool wantsHangup = false;
			const char digit = _vmPendingDigit[slot].exchange('\0', std::memory_order_acq_rel);
			if (digit != '\0')
			{
				wantsHangup = dispatchVoicemailMenuCommand(slot, callID, session,
					_vmMenus[slot].onDigit(digit));
			}
			else if (_vmLegs[slot].state() == VoicemailLeg::State::PlaybackDone)
			{
				_vmLegs[slot].reset();
				wantsHangup = dispatchVoicemailMenuCommand(slot, callID, session,
					_vmMenus[slot].onPlaybackDone());
			}

			if (!wantsHangup &&
				_vmSdJobState[slot].load(std::memory_order_acquire) == VmSdJobState::Done &&
				std::strncmp(_vmSdJob[slot].callId, callID.c_str(), sizeof(_vmSdJob[slot].callId) - 1) == 0)
			{
				wantsHangup = handleVoicemailSdJobDone(slot, callID, session);
			}

			if (wantsHangup)
			{
				// Deferred, same as the wall-clock expiry check below --
				// see dispatchVoicemailMenuCommand()'s doc comment for why
				// this must never call endCall() from inside this loop.
				toExpire.push_back(callID);
				continue;
			}

			// A Retrieval leg is never touched by the Deposit branch below,
			// and its deadline is re-armed per-message inside
			// handleVoicemailSdJobDone() instead of checked once here --
			// still worth the same wall-clock safety net, so fall through
			// to the shared expiry check.
		}
		else if (_vmLegs[slot].state() == VoicemailLeg::State::PlaybackDone)
		{
			// Deposit: greeting finished -> start recording.
			// Reuse the identity the leg was already claimed under (set at
			// startPlaying() time) rather than re-deriving from the session
			// -- session->getSrc() is the CALLER, not the mailbox owner.
			const std::string extension = _vmLegs[slot].extension();
			const std::string callId = _vmLegs[slot].callId();
			_vmLegs[slot].startRecording(_vmRecordBufs[slot], POCKETDIAL_VOICEMAIL_MAX_MESSAGE_BYTES,
				POCKETDIAL_VOICEMAIL_MAX_MESSAGE_BYTES, extension, callId);
		}

		// Wall-clock safety net: a caller whose audio silently stops
		// arriving (network drop, a phone that stops sending RTP) never
		// hits onCallerRtp()'s byte-cap and never sends a BYE either.
		if (session->isVoicemailDeadlineExpired(now))
		{
			toExpire.push_back(callID);
		}
	}

	for (const auto& callID : toExpire)
	{
		auto it = _sessions.find(callID);
		if (it == _sessions.end()) continue;
		sendVoicemailBye(callID, it->second);
	}
}

void RequestsHandler::sendVoicemailBye(const std::string& callID, const std::shared_ptr<Session>& session)
{
	auto src = session->getSrc();
	const std::string& dFrom = session->getDialogFrom();
	const std::string& dTo = session->getDialogTo();
	// Same From/To swap sweepSessionTimers() uses: we (the dialog's
	// original To/UAS) are now originating the BYE, so our own captured
	// To becomes the BYE's From and the caller's captured From becomes
	// its To.
	if (src && !dFrom.empty() && !dTo.empty())
	{
		auto b = buildServerBye(src->getNumber(), src->getAddress(), callID, dTo, dFrom);
		if (b) _outbox.emplace_back(src->getAddress(), std::move(b));
	}
	endCall(callID, src ? src->getNumber() : "", "700", "voicemail ended");
}

void RequestsHandler::releaseVoicemailLeg(int slot, const std::string& callId)
{
	if (slot < 0 || slot >= static_cast<int>(POCKETDIAL_MAX_VOICEMAIL_LEGS)) return;
	_vmRtpReceivers[slot].stop();
	_vmRtpSenders[slot].stop(callId);
	_vmLegs[slot].reset();
	// A stale menu's isDone()/state is a trap for the next call to claim
	// this slot (Fable-Low review) -- start() reinitializes it anyway, but
	// nothing should ever read it before that. Same for a leftover digit
	// press nobody will consume.
	_vmMenus[slot] = VoicemailMenu{};
	_vmPendingDigit[slot].store('\0', std::memory_order_release);
	// Deliberately DOES NOT touch _vmSdJobState[slot]: a job may still be
	// Pending (the caller hung up mid-fetch) or freshly Done with no
	// session left to consume it -- the SD task owns the Pending->Done
	// transition, and sweepVoicemailLegs()'s orphan sweep is what clears a
	// Done result with no live session on this slot back to Idle. Resetting
	// it here would let findFreeVoicemailSlot() hand this slot to a NEW
	// call while the SD task is still writing _vmRecordBufs[slot] for the
	// OLD one -- see VmSdJob::callId's doc comment.
}

void RequestsHandler::releaseMohPreviewLocked()
{
	if (_mohPreview.listener >= 0)
	{
		_holdMusic.removeListener(_mohPreview.listener);
	}
	_mohPreview = MohPreview{};
}

std::string RequestsHandler::mohPreviewExtension()
{
	std::lock_guard<std::mutex> lock(_mutex);
	return _mohPreview.active ? _mohPreview.extension : std::string{};
}

bool RequestsHandler::startMohPreview(const std::string& extension)
{
	// _mutex is NOT recursive, so this takes it once and every helper below is the
	// *Locked variant. Calling the public stopMohPreview() from in here would
	// self-deadlock the HTTP task.
	std::lock_guard<std::mutex> lock(_mutex);

	if (!_holdMusic.isLoaded() || _holdMusic.localPort() <= 0) return false;

	auto target = findClient(extension);
	if (!target.has_value() || !target.value()) return false;

	// Replace any previous preview rather than refusing. The realistic case is an
	// operator clicking twice; leaving the first dialog ringing forever is worse
	// than cancelling it.
	if (_mohPreview.active)
	{
		stopMohPreviewLocked();
	}

	const std::string activeIp  = _localIp;
	const std::string srcIpPort = activeIp + ":" + std::to_string(_serverPort);
	const sockaddr_in& addr     = target.value()->getAddress();
	const std::string destIpPort = sipwire::addrToIpPort(addr);

	_mohPreview.callId    = "Call-ID: " + IDGen::GenerateID(16) + "@" + activeIp;
	_mohPreview.extension = extension;
	_mohPreview.fromTag   = IDGen::GenerateID(9);
	_mohPreview.branch    = "z9hG4bK" + IDGen::GenerateID(12);
	_mohPreview.addr      = addr;
	_mohPreview.listener  = -1;
	_mohPreview.active    = true;

	// Offer the board's OWN media: sendonly from the MoH port, exactly what a
	// parked caller is answered with. The phone is the answerer here, so this is
	// an OFFER rather than an answer, but the body is the same shape.
	const std::string sdp = sipwire::makeSendonlySdp(activeIp, _holdMusic.localPort());

	std::ostringstream ss;
	ss << "INVITE sip:" << extension << "@" << destIpPort << " SIP/2.0\r\n"
	   << "Via: SIP/2.0/UDP " << srcIpPort << ";branch=" << _mohPreview.branch << "\r\n"
	   << "From: \"Hold Music\" <sip:" << pbx::kServiceMoh << "@" << srcIpPort << ">;tag=" << _mohPreview.fromTag << "\r\n"
	   << "To: <sip:" << extension << "@" << activeIp << ">\r\n"
	   << _mohPreview.callId << "\r\n"
	   << "CSeq: 1 INVITE\r\n"
	   << "Max-Forwards: 70\r\n"
	   << "Contact: <sip:" << pbx::kServiceMoh << "@" << srcIpPort << ";transport=UDP>\r\n"
	   << "User-Agent: pocket-dial\r\n"
	   << "Content-Type: application/sdp\r\n"
	   << "Content-Length: " << sdp.size() << "\r\n\r\n"
	   << sdp;

	auto inv = getMessageFromPool(ss.str(), addr);
	if (!inv)
	{
		_mohPreview = MohPreview{};   // pool exhausted: do not leave a phantom dialog
		return false;
	}
	inv->syncContentLength();
	// _asyncOutbox, NOT _outbox: this runs on the HTTP task, off the SIP receive
	// thread. handle()/tick() clear _outbox at the START of every pass, so an
	// INVITE queued there from here is wiped before anything drains it -- the
	// phone never rings while the API cheerfully reports "ringing". Found on
	// hardware: /api/moh/preview returned 200 and the SIP trace showed no INVITE
	// at all, only REGISTER/OPTIONS traffic. drainOutbox() merges _asyncOutbox
	// first, so the next tick() flushes this. Same rule as the CallEvent
	// callback's fork at :2932.
	_asyncOutbox.emplace_back(addr, std::move(inv));
	queueLog("MoH preview: ringing " + extension);
	return true;
}

bool RequestsHandler::handleMohPreviewOk(const std::shared_ptr<SipMessage>& data)
{
	if (!_mohPreview.active) return false;
	if (std::string(data->getCallID()) != _mohPreview.callId) return false;

	// They answered. Their 200 OK's SDP says where to send the music.
	if (_mohPreview.listener < 0)
	{
		std::string rtpIp;
		uint16_t    rtpPort = 0;
		if (sipwire::parseRtpTarget(std::string(data->getBody()), data->getSource(),
		                            rtpIp, rtpPort))
		{
			_mohPreview.listener = _holdMusic.addListener(rtpIp, rtpPort);
		}
		_mohPreview.toTag = siphdr::tagOf(data->getTo());

		queueLog(_mohPreview.listener >= 0
			? "MoH preview: " + _mohPreview.extension + " answered — streaming"
			: "MoH preview: " + _mohPreview.extension +
			  " answered but offered no usable RTP endpoint");
	}

	// ACK it, or the phone retransmits the 200 and eventually tears the call down.
	const std::string activeIp  = _localIp;
	const std::string srcIpPort = activeIp + ":" + std::to_string(_serverPort);
	const std::string destIpPort = sipwire::addrToIpPort(_mohPreview.addr);

	std::ostringstream ss;
	ss << "ACK sip:" << _mohPreview.extension << "@" << destIpPort << " SIP/2.0\r\n"
	   << "Via: SIP/2.0/UDP " << srcIpPort << ";branch=" << _mohPreview.branch << "a\r\n"
	   << "From: \"Hold Music\" <sip:" << pbx::kServiceMoh << "@" << srcIpPort << ">;tag=" << _mohPreview.fromTag << "\r\n"
	   << "To: <sip:" << _mohPreview.extension << "@" << activeIp << ">"
	   << (_mohPreview.toTag.empty() ? "" : ";tag=" + _mohPreview.toTag) << "\r\n"
	   << _mohPreview.callId << "\r\n"
	   << "CSeq: 1 ACK\r\n"
	   << "Max-Forwards: 70\r\nContent-Length: 0\r\n\r\n";

	if (auto ack = getMessageFromPool(ss.str(), _mohPreview.addr))
	{
		_outbox.emplace_back(_mohPreview.addr, std::move(ack));
	}
	return true;
}

bool RequestsHandler::handleMohPreviewFailure(const std::shared_ptr<SipMessage>& data)
{
	// The phone said no to the preview INVITE (486 busy, 480 unavailable, 487
	// cancelled, or any other final failure). Same contract onFinalFailure states
	// for every server-originated UAC: whoever claims it owes the ACK (RFC 3261
	// §17.1.1.3) and owes releasing the slot.
	//
	// Without this the preview was claimed by nobody: the failure fell through to
	// endHandle(), whose lookup of the preview's own From ("moh") matches no
	// registered client, so the else branch answered the declining phone with a
	// stray 404 -- and _mohPreview stayed active forever, a phantom dialog that
	// blocked every later preview and leaked its listener slot.
	if (!_mohPreview.active) return false;
	if (std::string(data->getCallID()) != _mohPreview.callId) return false;

	if (_mohPreview.toTag.empty())
	{
		// A failure response carries its own To tag; the ACK for a non-2xx must
		// echo it or the phone will not match the ACK to its transaction and keeps
		// retransmitting until Timer H (~32 s).
		_mohPreview.toTag = siphdr::tagOf(data->getTo());
	}

	const std::string activeIp   = _localIp;
	const std::string srcIpPort  = activeIp + ":" + std::to_string(_serverPort);
	const std::string destIpPort = sipwire::addrToIpPort(_mohPreview.addr);

	// RFC 3261 §17.1.1.3: the ACK for a non-2xx goes in the ORIGINAL INVITE
	// transaction, so it reuses the INVITE's branch exactly (no "a" suffix, unlike
	// the 2xx ACK in handleMohPreviewOk, which is a new transaction).
	std::ostringstream ss;
	ss << "ACK sip:" << _mohPreview.extension << "@" << destIpPort << " SIP/2.0\r\n"
	   << "Via: SIP/2.0/UDP " << srcIpPort << ";branch=" << _mohPreview.branch << "\r\n"
	   << "From: \"Hold Music\" <sip:" << pbx::kServiceMoh << "@" << srcIpPort
	   << ">;tag=" << _mohPreview.fromTag << "\r\n"
	   << "To: <sip:" << _mohPreview.extension << "@" << activeIp << ">"
	   << (_mohPreview.toTag.empty() ? "" : ";tag=" + _mohPreview.toTag) << "\r\n"
	   << _mohPreview.callId << "\r\n"
	   << "CSeq: 1 ACK\r\n"
	   << "Max-Forwards: 70\r\nContent-Length: 0\r\n\r\n";

	if (auto ack = getMessageFromPool(ss.str(), _mohPreview.addr))
	{
		// This runs on the SIP receive thread (onBusy/onUnavailable/etc), so
		// _outbox is the right queue here -- unlike startMohPreview, which is
		// driven from the HTTP task and must use _asyncOutbox.
		_outbox.emplace_back(_mohPreview.addr, std::move(ack));
	}

	queueLog("MoH preview: " + _mohPreview.extension + " declined the preview (" +
	         std::string(data->getHeader()) + ")");
	releaseMohPreviewLocked();
	return true;
}

bool RequestsHandler::handleMohPreviewEnd(const std::shared_ptr<SipMessage>& data)
{
	if (!_mohPreview.active) return false;
	if (std::string(data->getCallID()) != _mohPreview.callId) return false;

	// They hung up (BYE), or declined/cancelled (4xx/6xx). Either way the preview
	// is over: stop the music to this leg and free the slot.
	queueLog("MoH preview: ended (" + _mohPreview.extension + ")");
	releaseMohPreviewLocked();
	return true;
}

void RequestsHandler::stopMohPreview()
{
	std::lock_guard<std::mutex> lock(_mutex);
	stopMohPreviewLocked();
}

void RequestsHandler::stopMohPreviewLocked()
{
	// Every send below goes to _asyncOutbox for the same reason startMohPreview's
	// INVITE does: both callers (stopMohPreview, and startMohPreview replacing an
	// existing preview) run on the HTTP task, not the SIP receive thread.
	if (!_mohPreview.active) return;

	// Only BYE a dialog they actually answered — a To-tag is the proof. BYEing a
	// still-ringing INVITE is wrong (RFC 3261 wants a CANCEL) and phones reject it.
	if (!_mohPreview.toTag.empty())
	{
		const std::string activeIp  = _localIp;
		const std::string srcIpPort = activeIp + ":" + std::to_string(_serverPort);
		const std::string destIpPort = sipwire::addrToIpPort(_mohPreview.addr);

		std::ostringstream ss;
		ss << "BYE sip:" << _mohPreview.extension << "@" << destIpPort << " SIP/2.0\r\n"
		   << "Via: SIP/2.0/UDP " << srcIpPort << ";branch=" << _mohPreview.branch << "b\r\n"
		   << "From: \"Hold Music\" <sip:" << pbx::kServiceMoh << "@" << srcIpPort << ">;tag=" << _mohPreview.fromTag << "\r\n"
		   << "To: <sip:" << _mohPreview.extension << "@" << activeIp << ">;tag="
		   << _mohPreview.toTag << "\r\n"
		   << _mohPreview.callId << "\r\n"
		   << "CSeq: 2 BYE\r\n"
		   << "Max-Forwards: 70\r\nContent-Length: 0\r\n\r\n";
		if (auto bye = getMessageFromPool(ss.str(), _mohPreview.addr))
		{
			_asyncOutbox.emplace_back(_mohPreview.addr, std::move(bye));
		}
	}
	else
	{
		std::ostringstream ss;
		ss << "CANCEL sip:" << _mohPreview.extension << "@"
		   << sipwire::addrToIpPort(_mohPreview.addr) << " SIP/2.0\r\n"
		   << "Via: SIP/2.0/UDP " << _localIp << ":" << _serverPort
		   << ";branch=" << _mohPreview.branch << "\r\n"
		   << "From: \"Hold Music\" <sip:" << pbx::kServiceMoh << "@" << _localIp << ":" << _serverPort
		   << ">;tag=" << _mohPreview.fromTag << "\r\n"
		   << "To: <sip:" << _mohPreview.extension << "@" << _localIp << ">\r\n"
		   << _mohPreview.callId << "\r\n"
		   << "CSeq: 1 CANCEL\r\n"
		   << "Max-Forwards: 70\r\nContent-Length: 0\r\n\r\n";
		if (auto c = getMessageFromPool(ss.str(), _mohPreview.addr))
		{
			_asyncOutbox.emplace_back(_mohPreview.addr, std::move(c));
		}
	}

	releaseMohPreviewLocked();
}

bool RequestsHandler::startHoldMusic(const std::string& clipPath)
{
	// Deliberately tolerant at every step. Music on hold is a comfort feature; a
	// board whose card was pulled, or whose operator uploaded a 44.1 kHz stereo
	// MP3-converted-wrong, must still park calls. Each failure logs and leaves
	// park on its pre-#162 silent hold.
	if (!_holdMusic.loadClip(clipPath))
	{
		if (_holdMusic.lastLoadRefused())
		{
			queueLog("[WARN] MoH: clip at " + clipPath + " REFUSED -- PSRAM short, or over the " +
			         std::to_string(POCKETDIAL_CLIP_INTERNAL_MAX_BYTES) +
			         " B internal cap on a board without PSRAM (#466); parked callers will hear silence", true);
			return false;
		}
		queueLog("MoH: no clip at " + clipPath +
		         " (or not 8 kHz mono mu-law) — parked callers will hear silence", true);
		return false;
	}
	if (!_holdMusic.start())
	{
		queueLog("MoH: clip loaded but the stream would not start — silent hold", true);
		return false;
	}
	queueLog("MoH: " + std::to_string(_holdMusic.clipSeconds()) + "s clip on UDP " +
	         std::to_string(_holdMusic.localPort()));
	return true;
}

unsigned RequestsHandler::anchorCallLimit() const
{
	// TWO different ceilings, and conflating them is a real bug rather than a
	// tidiness point.
	//
	//   * POCKETDIAL_MAX_ANCHOR_CALLS sizes _mediaBridges and the per-call RTP
	//     arrays. It is a limit on the MACHINERY.
	//   * AnchorClient::maxConcurrentCalls() is what the plugged-in PROVIDER can
	//     actually drive. LoopbackAnchorClient returns a constant participant id
	//     ("mock-part-123"), and the engine keys its rx-audio fan-out on that id —
	//     so a second concurrent loopback call collides with the first and the
	//     fan-out feeds whichever bridge it finds first, silently starving the
	//     other leg. Not a crash: one-way audio with no diagnostic. 555 is
	//     reachable on default firmware, so this is not hypothetical.
	//
	// Taking the smaller means the array can be sized for the real trunk without
	// the mock inheriting a concurrency it cannot honour.
	unsigned providerLimit = 1;
	if (_anchorClient) providerLimit = _anchorClient->maxConcurrentCalls();
	if (providerLimit == 0) providerLimit = 1;   // a provider claiming 0 is a bug; refuse to divide by it

	const unsigned poolLimit = static_cast<unsigned>(POCKETDIAL_MAX_ANCHOR_CALLS);
	return (providerLimit < poolLimit) ? providerLimit : poolLimit;
}

unsigned RequestsHandler::activeAnchorCalls() const
{
	unsigned n = 0;
	for (const auto& b : _mediaBridges)
	{
		if (b.isActive()) ++n;
	}
	return n;
}

MediaBridge* RequestsHandler::acquireFreeAnchorBridge()
{
	// Refuse before handing out a slot the provider cannot service. The caller
	// treats nullptr as "at capacity" and answers 503, which is the honest result
	// — better than accepting a call that would come up with one-way audio.
	if (activeAnchorCalls() >= anchorCallLimit()) return nullptr;

	for (auto& b : _mediaBridges)
	{
		if (!b.isActive()) return &b;
	}
	return nullptr;
}

MediaBridge* RequestsHandler::bridgeForParticipant(const std::string& participantId)
{
	if (participantId.empty()) return nullptr;
	for (auto& b : _mediaBridges)
	{
		if (b.isFor(participantId)) return &b;
	}
	return nullptr;
}

bool RequestsHandler::allBridgesBusy() const
{
	// Must agree with acquireFreeAnchorBridge()'s refusal exactly, or the engine
	// reports capacity it will then decline to hand out.
	return activeAnchorCalls() >= anchorCallLimit();
}

bool RequestsHandler::anchorIsSynchronous() const
{
	return _anchorBootType == TelephonyProviderType::Loopback;
}

void RequestsHandler::onAnchorInvite(std::shared_ptr<SipMessage> data,
	const std::shared_ptr<SipClient>& caller)
{
	// 555 is a fixed feature code (like 777/440/888) with nothing dialed after
	// it, so the only sensible makeCall() destination is whoever dialed in —
	// see originateAnchorCall()'s doc comment for the trunk-access case, where a
	// real digit string follows. respondIfDisconnected=true: a bare 555 dial IS
	// the whole request, so "no anchor connected" must answer 404 itself.
	originateAnchorCall(std::move(data), caller, std::string(caller->getNumber()),
		/*respondIfDisconnected=*/true);
}

// ── Emergency call routing (Issue #166) ──────────────────────────────────────
//
// Reached only from onInvite's emergency intercept, which runs before every
// operator-configurable destination lookup. See EmergencyCall.hpp for why the
// dial plan cannot be trusted to carry this and why the intercept sits where it
// does. Caller holds _mutex.
void RequestsHandler::routeEmergencyCall(std::shared_ptr<SipMessage> data,
	const std::shared_ptr<SipClient>& caller,
	const pbx::EmergencyDial& emergency, const std::string& dialed)
{
	const std::string kind(emergency.isTest ? "TEST 933" : "911");
	const std::string from(data->getFromNumber());
	// Always the bare number. If the user dialed 9911 out of habit, the trunk
	// still gets "911" -- never the prefixed form, and never a stripped "11".
	const std::string bare(emergency.number);
	const std::string asDialed = emergency.hadTrunkPrefix ? " (dialed " + dialed + ")" : "";

	// Log BEFORE routing, so the attempt is on the record even if everything
	// after this line fails. This is the honest floor of Kari's Law's
	// notification requirement; the on-site notification hook itself is the
	// companion half of #166 and lands separately.
	queueLog("EMERGENCY: " + kind + " dialed by " + from + asDialed, true);

	// respondIfDisconnected=false: when no trunk is connected, originateAnchorCall
	// returns false having sent NOTHING, so this function owns the failure
	// response and the handset never receives two final responses to one INVITE.
	// NOT std::move: originateAnchorCall takes its shared_ptr by value, and this
	// function still needs `data` afterwards to build the failure response from.
	bool placed = false;
	bool codecRejected = false;
	if (originateAnchorCall(data, caller, bare, /*respondIfDisconnected=*/false, &placed,
		&codecRejected))
	{
		// The call leg is enqueued. NOW notify: 47 CFR 9.16(b)(2) wants the
		// notification contemporaneous with the call and not delaying it, and
		// both leave on the same drainOutbox() pass, so that holds literally
		// rather than approximately. Nothing in notifyEmergency() can fail in a
		// way this function has to handle -- see EmergencyNotifier.hpp.
		// `placed`, not `true`: the anchor may have ANSWERED with a 503 (every
		// bridge slot busy, session pool full, makeCall declined) and still
		// returned true. Telling the front desk a 911 call went through when it
		// was refused for capacity is the worst error this feature could make.
		notifyEmergency(emergency, from, dialed, /*routed=*/placed);
		return;
	}

	// ── No route. 503, and specifically not 404 ──────────────────────────────
	//
	// RFC 4497 §8.3.1 (BCP 117) covers exactly this condition -- a SIP INVITE
	// inbound with no outbound channel available: "If no suitable channel is
	// available, the gateway should use response code 503 (Service
	// Unavailable)." RFC 3398 §7.2.4.1's Q.850 mapping agrees, sending every
	// trunk-outage cause (34 no circuit, 38 network out of order, 41 temporary
	// failure, 42 congestion, 47 resource unavailable) to 503 while reserving
	// 404 for numbering-plan causes (1/2/3).
	//
	// 404 is not merely a worse choice here, it is a false statement. RFC 3261
	// §21.4.5 defines it as "the server has definitive information that the user
	// does not exist" -- but this PBX just recognised 911. It knows exactly what
	// the number is; only the trunk is missing. Telling someone dialing for help
	// that the number does not exist is the wrong answer to the wrong question.
	//
	// RFC 6881 itself specifies no code for this, because §8 SP-28 makes a
	// default mapping a MUST and so never contemplates a compliant proxy having
	// no route at all. 503 is the least-wrong answer to a state the BCP forbids.
	//
	// NO Retry-After. RFC 3261 §21.5.4: a client "SHOULD NOT forward any other
	// requests to that server for the duration specified in the Retry-After
	// header field, if present" -- making a handset back off the PBX after a
	// failed 911 attempt is the last thing anyone wants. Without it the UA
	// treats this as a plain failure and may immediately try again.
	auto response = getMessageFromPool(*data);
	if (!response)
	{
		// Pool exhausted: drop and let the peer retransmit (#101A). The log line
		// above already recorded the attempt, which is the part that matters.
		queueLog("EMERGENCY: " + kind + " from " + from +
			" NOT ROUTED and no message available to answer with", true);
		// Still notify. A 911 attempt that produced neither a call nor even a
		// failure response is the single most important thing to put in front of
		// a human, and the notification path has its own pooled messages.
		notifyEmergency(emergency, from, dialed, /*routed=*/false);
		return;
	}
	// A free-text reason phrase (RFC 3261 §7.2) that many handsets display.
	// "Service Unavailable" is true but says nothing; this says what happened.
	// Issue #314: same 503 either way, but the Warning text must say what
	// actually went wrong -- a codec-rejected offer is not a trunk outage, and
	// telling the caller's UA the wrong reason is the same honesty failure the
	// 503-vs-404 rationale above was written to avoid.
	const char* warningDetail = codecRejected
		? "no G.711 codec offered"
		: "no outbound trunk connected";
	response->setHeader("SIP/2.0 503 Emergency Call Not Routable");
	response->clearBody();
	response->addHeader("Warning", "399 " + _localIp +
		" \"Emergency call could not be routed: " + warningDetail + "\"");
	response->setVia(sipwire::viaWithReceived(data->getVia(), data->getSource()));
	_outbox.emplace_back(data->getSource(), std::move(response));

	queueLog("EMERGENCY: " + kind + " from " + from + " COULD NOT BE ROUTED (" +
		warningDetail + ") - answered 503", true);

	// 503 is enqueued; notify after it, same ordering rule as the routed path.
	notifyEmergency(emergency, from, dialed, /*routed=*/false);
}

// Issue #166 part 2. Kept to this one small function so the compliance-relevant
// ordering is visible in one place: every caller has already enqueued its
// response before reaching here, and nothing below can fail back into the call.
void RequestsHandler::notifyEmergency(const pbx::EmergencyDial& emergency,
	const std::string& fromExt, const std::string& dialed, bool routed)
{
	const pbx::E911Config& cfg = _cfg.e911Config();

	_e911Notifier.notify(cfg, emergency.isTest, fromExt, dialed,
		emergency.hadTrunkPrefix, routed);

	// Make the notified phones audibly alert, on top of the MESSAGE text. The
	// beep is the existing register-beep INVITE (auto-answer headers, no RTP),
	// reused because it is the one server-originated "make this phone make a
	// noise" path in the tree that is actually proven in production.
	//
	// Honest limitation, documented rather than hidden: sendBeep() SKIPS when
	// its bounded table is full (RegisterBeeper.cpp), which is right for a
	// cosmetic registration beep and is not a guarantee anyone should rely on
	// for 911. It is strictly additive here -- the syslog record and the SIP
	// MESSAGE are the notification; this is the "or hear it" half of 9.16(b)(2)
	// on a best-effort basis. A dedicated alert-INVITE table that cannot be
	// starved by registration churn is the follow-up.
	for (const std::string& ext : cfg.notifyExts)
	{
		if (ext.empty() || ext == fromExt)
		{
			// Never beep the phone that is dialing 911: it is mid-call setup and
			// an intercom INVITE at that moment is the last thing it needs.
			continue;
		}
		auto phone = findClient(ext);
		if (phone.has_value())
		{
			_beeper.sendBeep(phone.value());
		}
	}
}

bool RequestsHandler::originateAnchorCall(std::shared_ptr<SipMessage> data,
	const std::shared_ptr<SipClient>& caller, const std::string& destination,
	bool respondIfDisconnected, bool* placedOut, bool* codecRejectedOut)
{
	// Issue #166: this function's bool return means "took ownership of the
	// INVITE", NOT "the call was placed" -- eight refuse() paths answer 4xx/5xx
	// and still return true. The emergency notification must tell a human which
	// actually happened, so it asks for that second fact separately. Optimistic
	// default, cleared by refuse() and by the one unwind path that fails without
	// answering.
	if (placedOut) *placedOut = true;
	if (codecRejectedOut) *codecRejectedOut = false;
	const std::string activeIp = _localIp;
	const std::string callID(data->getCallID());
	// The remote target both this response's Contact and every later in-dialog
	// request (BYE/CANCEL/ACK) key on. For a plain 555 dial this is "555"; for a
	// dial-plan Trunk rule (Issue #165) it is whatever digits the caller actually
	// dialed — buildOkWithSdp() below already derives its own Contact this same
	// way (data->getToNumber()), so this just brings the refuse/ringing paths
	// into agreement with it. onCancel()/onBye()/onAck() additionally recognize
	// the session by isAnchor() so a non-"555" remote target still tears down
	// correctly (see those functions' comments).
	const std::string remoteExt(data->getToNumber());

	auto refuse = [&](const char* statusLine, const char* why) {
		if (placedOut) *placedOut = false;   // answered, but not placed (#166)
		auto msg = getMessageFromPool(*data);
		if (!msg) return;   // pool exhausted: drop, peer retransmits (#101A)
		msg->setHeader(statusLine);
		msg->clearBody();
		msg->setVia(sipwire::viaWithReceived(data->getVia(), data->getSource()));
		msg->setContact(buildContact(remoteExt));
		_outbox.emplace_back(data->getSource(), std::move(msg));
		queueLog("anchor(" + remoteExt + "): " + std::string(why) + " for "
			+ std::string(data->getFromNumber()), true);
	};

	if (!_anchorClient || !_anchorClient->isConnected())
	{
		// No provider selected, or it hasn't (yet) connected — same "feature not
		// actually available" honesty StubTelephonyProvider models. 404 rather
		// than 503: this is not a transient capacity problem, dialing in simply
		// doesn't resolve to anything right now. For a Trunk-routed call
		// (respondIfDisconnected=false), the caller (CallForker::routeDialPlan)
		// owns sending that 404 itself — its existing "rule matched but the
		// target doesn't resolve" tail — so this must not also answer, or the
		// handset gets two final responses to one INVITE.
		if (respondIfDisconnected)
		{
			refuse(SipMessageTypes::NOT_FOUND, "no anchor client connected");
		}
		else
		{
			queueLog("anchor(" + remoteExt + "): trunk call to " + destination +
				" refused, no anchor client connected", true);
		}
		return false;
	}

	// Anchor-bridge media is SERVER-terminated and speaks G.711 only (buildMediaSdp
	// below hardcodes PCMU; MediaBridge::onHandsetRtp only µ-law-decodes) — narrower
	// than the relay-level gate at the top of onInvite(), which admits G.722 because
	// a peer-to-peer pair may negotiate wideband between themselves. Same reasoning
	// as the 777 echo leg's gate above: a caller offering nothing but wideband gets
	// 488 here rather than an answer advertising a codec this leg will never decode.
	//
	// Issue #304: allowPcma=false too, same as 777 -- MediaBridge::onHandsetRtp
	// only µ-law-decodes, not A-law, and buildMediaSdp's answer is PCMU-only
	// regardless of what was offered, so a PCMA-only offer could never be
	// legally answered here.
	if (data->hasSdp() && !data->offersSupportedAudio(/*allowWideband=*/false, /*allowPcma=*/false))
	{
		if (codecRejectedOut)
		{
			// Issue #314: caller asked to build its own response for this reason
			// (routeEmergencyCall's purpose-built 503) rather than the generic 488
			// below -- send nothing here, or the handset gets two final responses
			// to one INVITE.
			*codecRejectedOut = true;
			if (placedOut) *placedOut = false;
			return false;
		}
		refuse("SIP/2.0 488 Not Acceptable Here", "no G.711 codec offered");
		return true;
	}

	// Where does this phone want its audio? Same c=/m= parse the 440/888 paths use.
	std::string destIp;
	uint16_t destPort = 0;
	if (!parseCallerRtp(data, destIp, destPort))
	{
		refuse(SipMessageTypes::BAD_REQUEST, "no usable RTP destination in INVITE");
		return true;
	}

	if (anchorIsSynchronous())
	{
		// Loopback: unchanged from before Stage B. makeCall()/dropCall() are cheap,
		// bounded (~40 ms) thread-joins, so calling them directly under _mutex is
		// safe (see anchorIsSynchronous()'s doc comment) — answer synchronously,
		// exactly as AnchorRouting_test.cpp requires.
		MediaBridge* bridge = acquireFreeAnchorBridge();
		if (!bridge)
		{
			// 503 + Retry-After, not 486 Busy Here: 486 means the CALLED PARTY is busy
			// (a final "don't retry this number" answer), but here nothing about the
			// dialed 555 code itself is busy — every anchor bridge SLOT is. 503 tells
			// the caller's UA this is a temporary capacity condition, matching what
			// the equivalent WAN-anchor wiring in the sibling commercial product does
			// for the same reason.
			refuse("SIP/2.0 503 Service Unavailable", "every anchor bridge slot busy");
			return true;
		}

		// makeCall() before startBridge(): a bridge with no far side to carry audio to
		// is pointless to stand up. `destination` is the caller's own number for a
		// plain 555 dial, or the dial-plan-transformed digit string for a Trunk rule
		// (Issue #165) — either way, the AnchorClient decides where it actually goes.
		// LoopbackAnchorClient resolves its own leg (ownLeg) SYNCHRONOUSLY, before any
		// Ringing/Answered event, so it can be bound to the bridge right away (see its
		// doc comment).
		std::string ownLeg;
		if (!_anchorClient->makeCall(destination, &ownLeg))
		{
			refuse("SIP/2.0 503 Service Unavailable", "anchor declined makeCall");
			return true;
		}

		if (!bridge->startBridge(destIp, destPort, callID, ownLeg,
			data->getTelephoneEventPayloadType()))
		{
			_anchorClient->dropCall(ownLeg);
			refuse("SIP/2.0 503 Service Unavailable", "media bridge failed to start");
			return true;
		}

		auto newSession = allocateSession(callID, caller);
		if (!newSession)
		{
			bridge->stopBridge();
			_anchorClient->dropCall(ownLeg);
			refuse("SIP/2.0 503 Service Unavailable", "session pool full");
			return true;
		}

		// Draw the answer BEFORE publishing the session — same "a pool refusal must
		// never strand a call that already mutated state" reasoning as onConferenceInvite
		// above. The SDP advertises THIS BRIDGE's receive port (not any other slot's):
		// that is where the handset must send its audio for the anchor to hear it.
		const std::string toTag = IDGen::GenerateID(9);
		// Echo the caller's telephone-event PT so DTMF reaches the anchored leg --
		// this is the path a voicemail or IVR menu will be driven over.
		const std::string sdpBody = buildMediaSdp(activeIp, bridge->receiverPort(),
			/*sendrecv=*/true, data->getTelephoneEventPayloadType());
		auto ok = buildOkWithSdp(data, activeIp, toTag, sdpBody);
		if (!ok)
		{
			bridge->stopBridge();
			_anchorClient->dropCall(ownLeg);
			queueLog("anchor(" + remoteExt + "): message pool exhausted, call unwound", true);
			if (placedOut) *placedOut = false;   // unwound, nothing sent (#166)
			return true;
		}

		// Per-session dummy dest (never a shared client) so a concurrent 777/440/888/555
		// call can't overwrite this call's destination identity. Always kAnchorCallExt
		// (not remoteExt): this is dialog bookkeeping isAnchor()-adjacent code keys on
		// (onReinvite/onUpdate), not the dialed digits, so it must stay stable across
		// both a plain 555 dial and a Trunk-routed one.
		auto dummyAnchor = allocateVirtualPeer(kAnchorCallExt, data->getSource());
		newSession->setDest(dummyAnchor);
		newSession->setAnchor(true);
		newSession->setAnchorParticipantId(ownLeg);
		// Issue #232's exact fix, missed on this branch. The async
		// CallEvent::Answered path (:434, its own comment cites #232 by name)
		// and the 777/888 virtual legs all record dialog headers at answer
		// time for one reason: forceDisconnect()'s and sweepSessionTimers()'s
		// #72 guard refuses to BYE a handset with an empty From/To, since
		// phones drop a malformed BYE. This SYNCHRONOUS branch (the one
		// LoopbackAnchorClient/host tests exercise, and any real deployment
		// where anchorIsSynchronous() is true) never set them at all, so
		// EVERY existing BYE-on-teardown path was already silently unable to
		// notify this call's handset before this line existed -- caught
		// while wiring #279's own new teardown BYE into the degraded-anchor
		// sweep (:8100ish) and finding its own #72 guard correctly refusing
		// to send, because there was nothing here to refuse with.
		newSession->setDialogHeaders(std::string(data->getFrom()),
			std::string(data->getTo()) + ";tag=" + toTag);
		_sessions.emplace(callID, newSession);
		newSession->setState(Session::State::Connected);

		_outbox.emplace_back(data->getSource(), std::move(ok));

		queueLog("anchor(" + remoteExt + "): " + std::string(caller->getNumber()) + " bridged (participant "
			+ ownLeg + "), media to " + destIp + ":" + std::to_string(destPort));
		return true;
	}

	// A real WAN-anchor client (Stage B): admission is capacity-only here —
	// makeCall() is a blocking TLS HTTP round trip (see anchorIsSynchronous()'s
	// doc comment), so it must never run under _mutex the way the synchronous
	// branch above does. startBridge() itself is deferred to the CallEvent::
	// Answered callback, once asyncMakeCall()'s worker actually returns a
	// participant id and the handset's RTP destination is still worth honoring.
	if (allBridgesBusy())
	{
		refuse("SIP/2.0 503 Service Unavailable", "every anchor bridge slot busy");
		return true;
	}

	auto newSession = allocateSession(callID, caller);
	if (!newSession)
	{
		refuse("SIP/2.0 503 Service Unavailable", "session pool full");
		return true;
	}

	// Per-session dummy dest (never a shared client) so a concurrent 777/440/888/555
	// call can't overwrite this call's destination identity; also what the ordinary
	// isDialogSourceAuthorized() BYE/CANCEL leg-IP check compares against (its
	// address is the caller's own, matching src — see that function's comment).
	auto dummyAnchor = allocateVirtualPeer(kAnchorCallExt, data->getSource());
	newSession->setDest(dummyAnchor);
	newSession->setInviteMessage(data);
	newSession->setAnchor(true);
	newSession->setState(Session::State::Invited);
	const std::string localTag = IDGen::GenerateID(9);
	newSession->setLocalTag(localTag);
	// ANCHOR_NO_ANSWER_TIMEOUT, not pbx::kNoAnswerTimeout — this leg rings a PSTN
	// destination, not an extension down the hall. See the constant's definition.
	newSession->armRingTimer(std::chrono::steady_clock::now() + ANCHOR_NO_ANSWER_TIMEOUT);
	_sessions.emplace(callID, newSession);

	auto ringing = getMessageFromPool(*data);
	if (ringing)
	{
		ringing->setHeader(SipMessageTypes::RINGING);
		ringing->clearBody();
		ringing->setVia(sipwire::viaWithReceived(data->getVia(), data->getSource()));
		ringing->setTo(std::string(data->getTo()) + ";tag=" + localTag);
		ringing->setContact(buildContact(remoteExt));
		_outbox.emplace_back(data->getSource(), std::move(ringing));
	}

	// `destination` is the caller's own number for a plain 555 dial, or the
	// dial-plan-transformed digit string for a Trunk rule (Issue #165) — see the
	// synchronous branch's comment above. Dispatched off the SIP thread; the
	// 200 OK follows later from the CallEvent::Answered callback once the far
	// leg actually connects.
	asyncMakeCall(destination, callID, caller->getNumber());
	queueLog("anchor(" + remoteExt + "): " + std::string(caller->getNumber()) + " ringing (async makeCall dispatched)");
	return true;
}

// ── Anchor async wrappers (Stage B) ──────────────────────────────────────────

bool RequestsHandler::bindOutboundParticipant(const std::string& callId, const std::string& ownLeg)
{
	if (callId.empty() || ownLeg.empty()) return false;
	std::lock_guard<std::mutex> lock(_mutex);
	auto it = _sessions.find(callId);
	if (it != _sessions.end() && it->second && it->second->isAnchor())
	{
		it->second->setAnchorParticipantId(ownLeg);
		return true;
	}
	// Issue #379: the session can legitimately be gone by now -- the handset
	// CANCELled during makeCall()'s TLS round trip and endCall() already
	// erased it. Binding silently would leave `ownLeg` live on the anchor
	// with nobody on the local end; the caller must drop it.
	return false;
}

void RequestsHandler::refuseRingingAnchor(const std::string& callId,
	std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>>& outbox)
{
	// Final response for an outbound anchor call that died before the far leg
	// connected: 503 the caller off the stored INVITE, exactly as tick()'s
	// no-answer reap does. endCall() itself never sends a SIP response, so every
	// still-ringing failure path must call this first or the handset rings on
	// with no final answer. Caller holds _mutex and picks the outbox for its
	// thread (_outbox on the SIP thread, _asyncOutbox from a worker).
	auto sit = _sessions.find(callId);
	if (sit == _sessions.end() || !sit->second) return;
	if (sit->second->getState() != Session::State::Invited) return;
	auto invite = sit->second->getInviteMessage();
	if (!invite) return;
	auto resp = getMessageFromPool(*invite);
	if (!resp) return;
	resp->setHeader("SIP/2.0 503 Service Unavailable");
	resp->clearBody();
	resp->setContact(buildContact(std::string(invite->getToNumber())));
	outbox.emplace_back(invite->getSource(), std::move(resp));
}

void RequestsHandler::asyncMakeCall(const std::string& destination, const std::string& callId,
	const std::string& callerNumber)
{
	if (!_anchorClient) return;
#if defined(ESP_PLATFORM) || defined(ESP32)
	struct MakeCallArg
	{
		// Default-initialized so cppcheck's uninitMemberVarNoCtor cannot fire on
		// the raw pointers. Every member is still aggregate-initialized at the
		// single call site below (C++17 keeps this an aggregate despite the
		// default member initializers), so behaviour is unchanged.
		AnchorClient* anchor = nullptr;
		std::string dest;
		std::string callId;
		std::string callerNumber;
		RequestsHandler* handler = nullptr;
	};
	auto* arg = new MakeCallArg{ _anchorClient, destination, callId, callerNumber, this };
	// 12288: makeCall is a TLS HTTPS round trip — same overflow as tel_start's
	// fetchToken (4096 bootlooped on real hardware).
	// CHECK the spawn: under heap pressure during an active call the 12 KB PSRAM
	// stack can fail to allocate; the outbound worker then never runs and the
	// call is silently never placed. Surface that (and free the arg) instead of
	// a silent, phantom non-call — mirrors asyncDropCall's check exactly.
	if (xTaskCreateWithCaps([](void* p) {
		auto* mca = static_cast<MakeCallArg*>(p);
		std::string ownLeg;
		if (!mca->anchor->makeCall(mca->dest, &ownLeg))
		{
			std::lock_guard<std::mutex> lock(mca->handler->_mutex);
			mca->handler->queueLog("[Telephony] Failed to initiate outbound call to " + mca->dest, true);
			// Off the SIP thread: 503 goes via _asyncOutbox (endCall() sends nothing).
			mca->handler->refuseRingingAnchor(mca->callId, mca->handler->_asyncOutbox);
			mca->handler->endCall(mca->callId, mca->callerNumber, mca->dest, "anchor call fail");
		}
		else
		{
			// Bind this origination's own leg to its session NOW (locks _mutex
			// internally) so a later Answered/Dropped maps to the right call when
			// several are in flight.
			const bool bound = mca->handler->bindOutboundParticipant(mca->callId, ownLeg);
			std::lock_guard<std::mutex> lock(mca->handler->_mutex);
			if (!bound && !ownLeg.empty())
			{
				// Issue #379: the handset hung up while makeCall() was still on
				// the wire (a ~0.8 s TLS round trip), so the CANCEL path's
				// endCall() already destroyed the session this leg belongs to.
				// makeCall() nonetheless SUCCEEDED, so 3CX now has a Dialing leg
				// that will ring the far party, be answerable and bill, with no
				// local party and nothing that will ever map an event back to
				// it. Drop it now. asyncDropCall() spawns its own worker, so it
				// is safe from this task and under _mutex (endCall() calls it
				// the same way). An empty ownLeg means makeCall() produced no
				// leg id at all -- nothing on the anchor to drop, so fall through
				// to the ordinary log exactly as before.
				mca->handler->queueLog("[Telephony] Outbound call to " + mca->dest +
					" was cancelled during makeCall — dropping orphaned leg " + ownLeg + " (#379)", true);
				mca->handler->asyncDropCall(ownLeg);
			}
			else
			{
				mca->handler->queueLog("[Telephony] Initiating outbound call to " + mca->dest);
			}
		}
		delete mca;
		vTaskDeleteWithCaps(NULL);   // created WithCaps(PSRAM)
	}, "tel_makecall", 12288, arg, 5, NULL, PD_TASK_STACK_CAPS) != pdPASS)
	{
		queueLog("[Telephony] asyncMakeCall: outbound worker xTaskCreate FAILED (heap exhausted) — call NOT placed", true);
		delete arg;
		// onAnchorInvite() already allocated the session and sent 180 Ringing; with
		// no worker nobody will ever answer or fail it, so without this the handset
		// rings until tick()'s no-answer reap fires ~20 s later. Do what that reap
		// does for a still-ringing anchor call right now: 503 the caller off the
		// stored INVITE (endCall() itself sends no SIP response), then tear the
		// session down. Runs on the SIP thread under _mutex (handler dispatch),
		// same as the synchronous anchor branch's direct endCall() call, so
		// _outbox (not _asyncOutbox) is the right queue.
		refuseRingingAnchor(callId, _outbox);
		endCall(callId, callerNumber, destination, "anchor worker spawn fail");
	}
#else
	spawnAnchorWorker([this, destination, callId, callerNumber]() {
		std::string ownLeg;
		if (!_anchorClient->makeCall(destination, &ownLeg))
		{
			std::lock_guard<std::mutex> lock(_mutex);
			queueLog("[Telephony] Failed to initiate outbound call to " + destination, true);
			// Off the SIP thread: 503 goes via _asyncOutbox (endCall() sends nothing).
			refuseRingingAnchor(callId, _asyncOutbox);
			endCall(callId, callerNumber, destination, "anchor call fail");
		}
		else
		{
			const bool bound = bindOutboundParticipant(callId, ownLeg);   // locks _mutex itself
			std::lock_guard<std::mutex> lock(_mutex);
			if (!bound && !ownLeg.empty())
			{
				// Issue #379: see the ESP branch above -- session already torn
				// down by a handset CANCEL mid-makeCall; drop the orphaned leg.
				queueLog("[Telephony] Outbound call to " + destination +
					" was cancelled during makeCall — dropping orphaned leg " + ownLeg + " (#379)", true);
				asyncDropCall(ownLeg);
			}
			else
			{
				queueLog("[Telephony] Initiating outbound call to " + destination);
			}
		}
	});
#endif
}

void RequestsHandler::asyncDropCall(const std::string& participantId)
{
	if (!_anchorClient) return;
#if defined(ESP_PLATFORM) || defined(ESP32)
	struct DropCallArg
	{
		// See MakeCallArg: default-initialized for cppcheck, still an aggregate.
		AnchorClient* anchor = nullptr;
		std::string partId;
		RequestsHandler* handler = nullptr;
	};
	auto* arg = new DropCallArg{ _anchorClient, participantId, this };
	// CHECK the spawn: under heap pressure during an active call the 12 KB PSRAM
	// stack can fail to allocate; the drop worker then never runs and the far leg
	// never tears down. Surface that (and free the arg) instead of a silent,
	// phantom non-drop.
	if (xTaskCreateWithCaps([](void* p) {
		auto* dca = static_cast<DropCallArg*>(p);
		dca->anchor->dropCall(dca->partId);
		delete dca;
		vTaskDeleteWithCaps(NULL);
	}, "tel_dropcall", 12288, arg, 5, NULL, PD_TASK_STACK_CAPS) != pdPASS)
	{
		queueLog("[Telephony] asyncDropCall: drop worker xTaskCreate FAILED (heap exhausted) — leg NOT dropped", true);
		delete arg;
	}
#else
	spawnAnchorWorker([this, participantId]() {
		_anchorClient->dropCall(participantId);
	});
#endif
}

void RequestsHandler::asyncAnswerCall(const std::string& participantId)
{
	// Answer an inbound upstream participant off the SIP thread (the POST is a
	// TLS round trip). Mirrors asyncDropCall's threading/lifetime rules exactly.
	if (!_anchorClient) return;
#if defined(ESP_PLATFORM) || defined(ESP32)
	struct AnswerCallArg
	{
		// See MakeCallArg: default-initialized for cppcheck, still an aggregate.
		AnchorClient* anchor = nullptr;
		std::string partId;
		RequestsHandler* handler = nullptr;
	};
	auto* arg = new AnswerCallArg{ _anchorClient, participantId, this };
	// CHECK the spawn: same heap-pressure hazard asyncDropCall's own comment
	// describes -- without this check a failed allocation leaks `arg` and
	// silently never answers the call.
	if (xTaskCreateWithCaps([](void* p) {
		auto* aca = static_cast<AnswerCallArg*>(p);
		if (!aca->anchor->answerCall(aca->partId))
		{
			std::lock_guard<std::mutex> lock(aca->handler->_mutex);
			aca->handler->queueLog("[Telephony] Failed to answer inbound participant " + aca->partId, true);
		}
		delete aca;
		vTaskDeleteWithCaps(NULL);
	}, "tel_answer", 12288, arg, 5, NULL, PD_TASK_STACK_CAPS) != pdPASS)
	{
		queueLog("[Telephony] asyncAnswerCall: answer worker xTaskCreate FAILED (heap exhausted) — participant NOT answered", true);
		delete arg;
	}
#else
	spawnAnchorWorker([this, participantId]() {
		if (!_anchorClient->answerCall(participantId))
		{
			std::lock_guard<std::mutex> lock(_mutex);
			queueLog("[Telephony] Failed to answer inbound participant " + participantId, true);
		}
	});
#endif
}

#if !defined(ESP_PLATFORM) && !defined(ESP32)
// Spawn a host anchor worker that runs `job` then flips its done-flag. The flag
// lets reapAnchorWorkers() join+erase finished threads in tick(), so the live
// thread count tracks in-flight calls rather than growing without bound. Also
// reaped opportunistically here, so a steady call rate never lets the vector grow.
void RequestsHandler::spawnAnchorWorker(std::function<void()> job)
{
	auto done = std::make_shared<std::atomic<bool>>(false);
	std::thread worker([job = std::move(job), done]() {
		job();
		done->store(true, std::memory_order_release);
	});
	std::lock_guard<std::mutex> lock(_anchorWorkMutex);
	reapFinishedLocked();   // reap already-finished siblings before appending
	_anchorWorkThreads.push_back(AnchorWorker{ std::move(worker), std::move(done) });
}

// Caller MUST hold _anchorWorkMutex. Join + erase every worker whose done-flag
// is set.
void RequestsHandler::reapFinishedLocked()
{
	for (auto it = _anchorWorkThreads.begin(); it != _anchorWorkThreads.end(); )
	{
		if (it->done && it->done->load(std::memory_order_acquire))
		{
			if (it->thread.joinable()) it->thread.join();
			it = _anchorWorkThreads.erase(it);
		}
		else
		{
			++it;
		}
	}
}

// Called from tick(): reap finished anchor workers. drainAll blocks until every
// worker has finished (the destructor's belt-and-suspenders join).
void RequestsHandler::reapAnchorWorkers(bool drainAll)
{
	std::vector<AnchorWorker> toJoin;
	{
		std::lock_guard<std::mutex> lock(_anchorWorkMutex);
		if (drainAll)
		{
			toJoin = std::move(_anchorWorkThreads);
			_anchorWorkThreads.clear();
		}
		else
		{
			reapFinishedLocked();
			return;
		}
	}
	// drainAll: join OUTSIDE the lock, so a still-running worker that ever needed
	// _anchorWorkMutex (it doesn't today, but be safe) can't deadlock us.
	for (auto& w : toJoin)
	{
		if (w.thread.joinable()) w.thread.join();
	}
}
#endif

// ── Inbound anchor call dispatch (Stage B) ───────────────────────────────────

void RequestsHandler::routeInboundAnchorCall(const std::string& participantId, const std::string& callerId)
{
	// Runs under _mutex (the CallEvent callback holds it). The monitored DN
	// (_anchorRouteDn) is a Telephony route point, not a phone, so the DEFAULT is
	// RING-ALL: fork an offerless INVITE to every registered extension, first
	// answer wins. _anchorRouteDn is only the gate that says this anchor is
	// configured to take inbound calls at all — TelephonyAnchorClient's own
	// handleWsEvent() already gates every WS event on the entity's dn matching
	// this exact string before the event ever reaches here (an event for any
	// other dn is silently dropped inside the client itself), so there is
	// nothing left here to key on except "is one configured".
	const std::string& dn = _anchorRouteDn;
	if (dn.empty())
	{
		queueLog("[Telephony] Inbound: no route DN configured — dropping participant " + participantId, true);
		asyncDropCall(participantId);
		return;
	}

	if (allBridgesBusy())
	{
		queueLog("[Telephony] Inbound: all media bridges busy — dropping inbound to " + dn);
		asyncDropCall(participantId);
		return;
	}

	// Refuse a second inbound while one is already ringing/up (keyed by the
	// inbound flag) — POCKETDIAL_MAX_ANCHOR_CALLS is 1 today, so allBridgesBusy()
	// above would already have caught this once the first leg is BRIDGED, but a
	// still-ringing (not yet bridged) first inbound leg holds no bridge yet.
	for (const auto& [cid, s] : _sessions)
	{
		if (s->isAnchorInbound() && s->getState() != Session::State::Bye)
		{
			queueLog("[Telephony] Inbound: a call is already in progress — dropping new inbound");
			asyncDropCall(participantId);
			return;
		}
	}

	// ── Track A's DID -> extension hook ──────────────────────────────────────
	// DidMapping is a bounded, no-I/O, no-heap linear scan over at most
	// POCKETDIAL_MAX_DID_MAPPINGS entries — safe to call directly under _mutex,
	// the same as any other small in-memory config lookup on this codebase's
	// dashboard/config tables (unlike makeCall/dropCall/answerCall, which must go
	// through the async* wrappers because THEY do TLS I/O; this does neither).
	// DidMapping's "did" field is entered by the operator as the LITERAL route DN
	// string, not a free-form DID/DDI — matching the note above that
	// TelephonyAnchorClient's own handleWsEvent() already filters to exactly this
	// dn, so no normalization/E.164-suffix matching is meaningful here either.
	std::string mappedExt = _didMapping.extensionForDid(dn);
	std::vector<std::shared_ptr<SipClient>> targets;
	if (!mappedExt.empty())
	{
		auto mapped = findClient(mappedExt);
		if (mapped.has_value() && !(*mapped)->getNumber().empty())
		{
			targets.push_back(*mapped);
		}
		else
		{
			queueLog("[Telephony] Inbound: DID " + dn + " maps to extension " +
			         mappedExt + " but it is not registered — falling back to ring-all", true);
		}
	}
	if (targets.empty())
	{
		// RING-ALL fallback: gather the live registrar set. We hold _mutex, so
		// reading _clientPool directly is safe (an empty number ⇒ free pool slot).
		for (const auto& client : _clientPool)
		{
			if (!client->getNumber().empty())
			{
				targets.push_back(client);
			}
		}
	}
	if (targets.empty())
	{
		queueLog("[Telephony] Inbound: no extensions registered — dropping participant " + participantId, true);
		asyncDropCall(participantId);
		return;
	}

	// Sanitised caller label for the From display-name (quoted token: no '"'/CR/LF).
	std::string callerDisplay = callerId.empty() ? std::string("PSTN") : callerId;
	callerDisplay.erase(std::remove_if(callerDisplay.begin(), callerDisplay.end(),
		[](char c){ return c == '"' || c == '\r' || c == '\n'; }), callerDisplay.end());
	if (callerDisplay.empty()) callerDisplay = "PSTN";

	const std::string activeIp = _localIp;
	// Key the session by the FULL header-line form ("Call-ID: <id>") so the
	// handsets' 200 OK/486/487 responses — which getSession() looks up via
	// SipMessage::getCallID() (which returns the whole line, name included) —
	// match. The forked INVITEs carry the bare <id> as the header value
	// (stripHeaderName on the getter), which the phones echo back verbatim.
	std::string callId  = std::string("Call-ID: ") + IDGen::GenerateID(16) + "@" + activeIp;
	std::string branch  = "z9hG4bK" + IDGen::GenerateID(12);
	std::string fromTag = IDGen::GenerateID(9);

	// One session backs the whole fork: a synthetic PSTN src (zeroed address —
	// only its label feeds getSrc() snapshots/CDR, never routed/looked-up), with
	// every forked leg sharing the Call-ID/Via branch/From-tag so each is a
	// single cancellable transaction toward its phone. dest stays unset until a
	// winner answers; pendingTargets holds the ringing legs.
	sockaddr_in pstnAddr{};
	pstnAddr.sin_family = AF_INET;
	auto pstn = allocateVirtualPeer(callerDisplay, pstnAddr);
	auto session = allocateSession(callId, pstn);
	if (!session)
	{
		queueLog("[Telephony] Inbound: session pool exhausted — dropping", true);
		asyncDropCall(participantId);
		return;
	}
	session->setAnchor(true);
	session->setAnchorInbound(true);
	session->setState(Session::State::Invited);
	session->setLocalTag(fromTag);
	session->setUacBranch(branch);
	session->setAnchorParticipantId(participantId);
	session->setPendingTargets(targets);
	session->armRingTimer(std::chrono::steady_clock::now() + pbx::kNoAnswerTimeout);
	_sessions.emplace(callId, session);

	// Delayed-offer INVITE per target (no SDP): the single-start MediaBridge
	// can't advertise a port before it binds, and the winning handset's 200 OK
	// carries its own offer — our ACK answers it (onInboundAnchorOk). No
	// auto-answer headers: the extensions should genuinely RING.
	for (const auto& target : targets)
	{
		buildInboundInviteFork(session, target, callerDisplay);
	}
	queueLog("[Telephony] Inbound: ringing " + std::to_string(targets.size()) +
	         " extension(s) for participant " + participantId +
	         (mappedExt.empty() ? " (ring-all)" : (" (DID-mapped to " + mappedExt + ")")));
}

void RequestsHandler::buildInboundInviteFork(const std::shared_ptr<Session>& session,
	const std::shared_ptr<SipClient>& target, const std::string& callerDisplay)
{
	// One delayed-offer INVITE toward `target`, reusing the session's shared
	// Call-ID/Via branch/From-tag. The dialog's From/To/Contact user is the
	// target's own DN (matched verbatim when it answers/cancels); the display
	// name presents the anchor's caller.
	const std::string activeIp = _localIp;
	const std::string srcIpPort = activeIp + ":" + std::to_string(_serverPort);
	const std::string dn = target->getNumber();
	const std::string destIpPort = sipwire::addrToIpPort(target->getAddress());

	std::ostringstream ss;
	ss << "INVITE sip:" << dn << "@" << destIpPort << " SIP/2.0\r\n"
	   << "Via: SIP/2.0/UDP " << srcIpPort << ";branch=" << session->getUacBranch() << "\r\n"
	   << "From: \"" << callerDisplay << "\" <sip:" << dn << "@" << srcIpPort << ">;tag=" << session->getLocalTag() << "\r\n"
	   << "To: <sip:" << dn << "@" << activeIp << ">\r\n"
	   << "Call-ID: " << stripHeaderName(session->getCallID()) << "\r\n"   // getCallID() returns the full line
	   << "CSeq: 1 INVITE\r\n"
	   << "Max-Forwards: 70\r\n"
	   << "Contact: <sip:" << dn << "@" << srcIpPort << ";transport=UDP>\r\n"
	   << "Content-Length: 0\r\n\r\n";

	auto invite = getMessageFromPool(ss.str(), target->getAddress());
	if (!invite) return;   // pool exhausted: skip this target (#101A)
	invite->syncContentLength();
	// The CallEvent callback runs OFF the SIP receive thread — _asyncOutbox
	// survives the per-pass _outbox.clear() in handle()/tick() (same rule as the
	// WS 200 OK/BYE the Answered/Dropped branches use).
	_asyncOutbox.emplace_back(target->getAddress(), std::move(invite));
}

std::shared_ptr<SipMessage> RequestsHandler::buildInboundCancelTo(const std::shared_ptr<Session>& session,
	const std::shared_ptr<SipClient>& target)
{
	if (!target) return nullptr;

	const std::string activeIp = _localIp;
	const std::string srcIpPort = activeIp + ":" + std::to_string(_serverPort);
	const std::string dn = target->getNumber();
	const std::string destIpPort = sipwire::addrToIpPort(target->getAddress());
	// The fork INVITE's From display is the anchor's caller label, which is
	// exactly the virtual src peer's number — so getSrc()->getNumber()
	// reproduces it byte-for-byte for the match.
	const std::string srcNum = session->getSrc() ? session->getSrc()->getNumber() : std::string("PSTN");

	// CANCEL matches the forked INVITE transaction at `target`: identical
	// Request-URI, top Via branch (shared by the whole fork), From (+tag), To (no
	// tag — no final response was accepted), Call-ID, and CSeq number with method
	// CANCEL.
	std::ostringstream cs;
	cs << "CANCEL sip:" << dn << "@" << destIpPort << " SIP/2.0\r\n"
	   << "Via: SIP/2.0/UDP " << srcIpPort << ";branch=" << session->getUacBranch() << "\r\n"
	   << "From: \"" << srcNum << "\" <sip:" << dn << "@" << srcIpPort << ">;tag=" << session->getLocalTag() << "\r\n"
	   << "To: <sip:" << dn << "@" << activeIp << ">\r\n"
	   << "Call-ID: " << stripHeaderName(session->getCallID()) << "\r\n"   // getCallID() returns the full line
	   << "CSeq: 1 CANCEL\r\n"
	   << "Max-Forwards: 70\r\n"
	   << "Content-Length: 0\r\n\r\n";
	return getMessageFromPool(cs.str(), target->getAddress());
}

std::shared_ptr<SipMessage> RequestsHandler::buildInboundCancel(const std::shared_ptr<Session>& session)
{
	// Back-compat single-leg wrapper: CANCEL the session's current dest (the
	// answered/answering handset). Ring-all loser teardown uses
	// buildInboundCancelTo() directly per target instead.
	return buildInboundCancelTo(session, session->getDest());
}

void RequestsHandler::ackInboundFinal(const std::shared_ptr<Session>& session, const std::shared_ptr<SipMessage>& data)
{
	// RFC 3261 §17.1.1.3: ACK a non-2xx final within the INVITE transaction. Same
	// top Via branch as the forked INVITE (the shared fork branch), To from the
	// response (carries the leg's tag), CSeq 1 ACK. The responding phone is the
	// packet source.
	const std::string activeIp = _localIp;
	const std::string srcIpPort = activeIp + ":" + std::to_string(_serverPort);
	const std::string dn(data->getToNumber());
	const std::string destIpPort = sipwire::addrToIpPort(data->getSource());
	const std::string srcNum = session->getSrc() ? session->getSrc()->getNumber() : std::string("PSTN");

	std::ostringstream ack;
	ack << "ACK sip:" << dn << "@" << destIpPort << " SIP/2.0\r\n"
	    << "Via: SIP/2.0/UDP " << srcIpPort << ";branch=" << session->getUacBranch() << "\r\n"
	    << "From: \"" << srcNum << "\" <sip:" << dn << "@" << srcIpPort << ">;tag=" << session->getLocalTag() << "\r\n"
	    << "To: " << stripHeaderName(data->getTo()) << "\r\n"
	    << "Call-ID: " << stripHeaderName(session->getCallID()) << "\r\n"   // getCallID() returns the full line
	    << "CSeq: 1 ACK\r\n"
	    << "Max-Forwards: 70\r\n"
	    << "Content-Length: 0\r\n\r\n";
	auto msg = getMessageFromPool(ack.str(), data->getSource());
	if (msg) _outbox.emplace_back(data->getSource(), std::move(msg));
}

void RequestsHandler::onInboundAnchorOk(const std::shared_ptr<SipMessage>& ok, const std::shared_ptr<Session>& session)
{
	// The handset answered our INVITE (server-as-UAC). Learn its tag + RTP, bring
	// up the media bridge, ACK with our SDP answer (delayed-offer model), then
	// answer upstream. Runs on the SIP receive thread under _mutex.
	session->clearRingTimer();

	const std::string activeIp = _localIp;
	const std::string srcIpPort = activeIp + ":" + std::to_string(_serverPort);
	const std::string callId(session->getCallID());          // full line — the _sessions key
	const std::string callIdHdr = stripHeaderName(callId);   // bare value for the wire

	// RING-ALL: dest is unset until a forked leg answers. The answering phone IS
	// the OK's source address, so resolve it (mirrors the broadcast winner
	// lookup); fall back to a previously-bound dest for the winner's own 200 OK
	// retransmits.
	auto answering = findClientByAddress(ok->getSource());
	std::shared_ptr<SipClient> handset = answering.has_value() ? answering.value() : session->getDest();
	if (!handset)
	{
		return;   // can't identify the answering extension — ignore
	}

	// Loser-race: a DIFFERENT extension answered after another leg already won
	// and bridged (its 200 OK crossed our CANCEL). RFC 3261 §9 — we must ACK then
	// BYE that orphan 2xx, but must NOT disturb the live bridge or the upstream
	// leg.
	if (session->getState() == Session::State::Connected &&
	    session->getDest() && handset->getNumber() != session->getDest()->getNumber())
	{
		const std::string orphanIpPort = sipwire::addrToIpPort(handset->getAddress());
		const std::string orphanFrom = "\"" + (session->getSrc() ? session->getSrc()->getNumber() : std::string("PSTN")) +
		                               "\" <sip:" + handset->getNumber() + "@" + srcIpPort + ">;tag=" + session->getLocalTag();
		const std::string orphanAckBranch = "z9hG4bK" + IDGen::GenerateID(12);
		std::ostringstream oack;
		oack << "ACK sip:" << handset->getNumber() << "@" << orphanIpPort << " SIP/2.0\r\n"
		     << "Via: SIP/2.0/UDP " << srcIpPort << ";branch=" << orphanAckBranch << "\r\n"
		     << "From: " << orphanFrom << "\r\n"
		     << "To: " << stripHeaderName(ok->getTo()) << "\r\n"
		     << "Call-ID: " << callIdHdr << "\r\n"
		     << "CSeq: 1 ACK\r\n"
		     << "Max-Forwards: 70\r\n"
		     << "Content-Length: 0\r\n\r\n";
		auto oackMsg = getMessageFromPool(oack.str(), handset->getAddress());
		if (oackMsg) _outbox.emplace_back(handset->getAddress(), std::move(oackMsg));
		auto obye = buildServerBye(handset->getNumber(), handset->getAddress(), callId, orphanFrom,
		                           std::string(ok->getTo()));
		if (obye) _outbox.emplace_back(handset->getAddress(), std::move(obye));
		queueLog("[Telephony] Inbound: extra answer from " + handset->getNumber() + " — rejected (call already up)");
		return;
	}

	// First answer wins: bind this phone as the dialog's dest for the rest of the call.
	if (!session->getDest())
	{
		session->setDest(handset);
	}

	// Handset's To-tag — needed on every in-dialog request we now send (ACK, BYE).
	std::string toHdr(ok->getTo());
	std::string remoteTag;
	size_t tp = toHdr.find(";tag=");
	if (tp != std::string::npos)
	{
		remoteTag = toHdr.substr(tp + 5);
		size_t e = remoteTag.find_first_of(";> \r\n\t");
		if (e != std::string::npos) remoteTag.erase(e);
	}
	session->setRemoteTag(remoteTag);

	// Rebuild the dialog's local From verbatim (display = src label, user = DN,
	// our tag) so ACK/BYE match the INVITE. To = the phone's full To header
	// (carries its tag).
	const std::string fromHeader = "\"" + (session->getSrc() ? session->getSrc()->getNumber() : std::string("PSTN")) +
	                               "\" <sip:" + handset->getNumber() + "@" + srcIpPort + ">;tag=" + session->getLocalTag();
	const std::string destIpPort = sipwire::addrToIpPort(handset->getAddress());

	// Idempotency: the phone retransmits its 200 OK until it sees our ACK. The
	// FIRST one (still Invited) brings up the bridge and answers upstream; a
	// retransmit arriving after we are Connected must ONLY re-emit the ACK (with
	// the same answer) — never start a second bridge (which would fail and tear
	// the live call down).
	const bool already = (session->getState() == Session::State::Connected);
	std::string handsetIp; uint16_t handsetPort = 0;
	std::string sdpAnswer;
	bool bridged = false;
	const std::string inPart = session->getAnchorParticipantId();
	if (already)
	{
		// Re-ACK retransmit — reuse THIS call's already-up bridge.
		if (MediaBridge* b = bridgeForParticipant(inPart))
		{
			sdpAnswer = buildMediaSdp(activeIp, b->receiverPort(), /*sendrecv=*/true);
			bridged = true;   // re-ACK only; bridge already up
		}
	}
	else if (parseCallerRtp(ok, handsetIp, handsetPort))
	{
		// Claim a free media bridge for this inbound call.
		MediaBridge* b = bridgeForParticipant(inPart);
		if (!b) b = acquireFreeAnchorBridge();
		if (b && b->startBridge(handsetIp, handsetPort, callId, inPart))
		{
			const int rxPort = b->receiverPort();
			sdpAnswer = buildMediaSdp(activeIp, rxPort, /*sendrecv=*/true);
			bridged = true;
			queueLog("[Telephony] Inbound: handset " + handsetIp + ":" + std::to_string(handsetPort) +
			         " answered; bridge up (rx " + std::to_string(rxPort) + ")");
		}
	}
	else
	{
		queueLog("[Telephony] Inbound: no usable SDP / bridge failed — tearing down", true);
	}

	// ACK the 2xx (RFC 3261 §13.2.2.4): a NEW transaction branch, CSeq 1 ACK.
	// Carries our SDP answer on success; on failure it is sent bodyless purely to
	// quench the phone's 200 retransmits before we BYE it.
	const std::string ackBranch = "z9hG4bK" + IDGen::GenerateID(12);
	std::ostringstream ack;
	ack << "ACK sip:" << handset->getNumber() << "@" << destIpPort << " SIP/2.0\r\n"
	    << "Via: SIP/2.0/UDP " << srcIpPort << ";branch=" << ackBranch << "\r\n"
	    << "From: " << fromHeader << "\r\n"
	    << "To: " << stripHeaderName(ok->getTo()) << "\r\n"
	    << "Call-ID: " << callIdHdr << "\r\n"
	    << "CSeq: 1 ACK\r\n"
	    << "Max-Forwards: 70\r\n";
	if (bridged && !sdpAnswer.empty())
	{
		ack << "Content-Type: application/sdp\r\n"
		    << "Content-Length: " << sdpAnswer.size() << "\r\n\r\n"
		    << sdpAnswer;
	}
	else
	{
		ack << "Content-Length: 0\r\n\r\n";
	}
	auto ackMsg = getMessageFromPool(ack.str(), handset->getAddress());
	if (ackMsg) _outbox.emplace_back(handset->getAddress(), std::move(ackMsg));

	if (already)
	{
		return;   // retransmitted 200 OK: ACK re-sent, nothing else to do
	}

	if (!bridged)
	{
		// Couldn't bridge: hang up both legs. BYE the handset (new CSeq 2
		// transaction), drop the upstream participant, end the session.
		auto bye = buildServerBye(handset->getNumber(), handset->getAddress(), callId, fromHeader,
		                          std::string(ok->getTo()));
		if (bye) _outbox.emplace_back(handset->getAddress(), std::move(bye));
		asyncDropCall(session->getAnchorParticipantId());
		session->setAnchorLegReleased();   // #379: endCall() must not drop it again
		endCall(callId, session->getSrc() ? session->getSrc()->getNumber() : "", handset->getNumber(),
		        "inbound bridge failed");
		return;
	}

	// Issue #232's exact gap, a SECOND independent instance of it: found
	// while wiring #279's own teardown BYE and checking every setAnchor(true)
	// call site for the same omission, not just the one that broke the
	// original repro. This function already builds fromHeader/ok->getTo()
	// above for the "couldn't bridge" BYE (:4652) -- the same pair belongs on
	// the session once the call actually succeeds, or forceDisconnect() and
	// #279's degraded-anchor sweep can never BYE this handset either, exactly
	// as they silently couldn't for the outbound case before that fix.
	session->setDialogHeaders(fromHeader, std::string(ok->getTo()));
	session->setState(Session::State::Connected);
	// Tell the upstream to connect the PSTN leg; its Connected upsert opens the
	// PCM streams (startMediaStreams) so audio flows handset RTP <-> bridge <-> PCM <-> upstream.
	asyncAnswerCall(session->getAnchorParticipantId());

	// RING-ALL: this leg won — CANCEL every other still-ringing fork so the other
	// phones stop. The winner is now dest; the rest live in pendingTargets. Clear
	// it afterward so the no-answer / upstream-abandon teardown paths don't
	// re-CANCEL an already-answered call.
	for (const auto& target : session->getPendingTargets())
	{
		if (target->getNumber() != handset->getNumber())
		{
			auto cancel = buildInboundCancelTo(session, target);
			if (cancel) _outbox.emplace_back(target->getAddress(), std::move(cancel));
		}
	}
	session->setPendingTargets({});
}

void RequestsHandler::onTrying(std::shared_ptr<SipMessage> data)
{
	// Our own MoH preview INVITE's 100 Trying. Same claim the beep makes in
	// onRinging: this is a provisional to US, the preview is a server-originated
	// UAC with no Session, and its From ("moh") resolves to no registered
	// extension -- so falling through to endHandle() below answers the phone that
	// is currently ringing with a stray 404 Not Found. Observed on hardware.
	if (mohPreviewOwnsCallID(data->getCallID()))
	{
		return;
	}

	auto session = getSession(data->getCallID());
	if (session.has_value() && session.value()->isBroadcast())
	{
		return;
	}
	// Inbound anchor leg (server is UAC): the handset's 100 Trying is a
	// provisional to US — swallow it rather than echoing it at the handset (see
	// onRinging below).
	if (session.has_value() && session.value()->isAnchorInbound())
	{
		return;
	}
	endHandle(data->getFromNumber(), data);
}

void RequestsHandler::onRinging(std::shared_ptr<SipMessage> data)
{
	// A 180 to our own register-beep INVITE (drawbridge #178). Recognise it and
	// stop — nothing more. Unlike the 480/486/487 claims in onBusy() /
	// onUnavailable() / onReqTerminated(), this deliberately does NOT call
	// _beeper.handleInviteFailure(): a 180 is provisional (RFC 3261 §17.1.1), it
	// takes no ACK and does not end the INVITE transaction, so the beep dialog is
	// still live and must keep its slot until a real final response or sweep().
	// What it must not do is fall through to endHandle(data->getFromNumber(),
	// ...) below, which resolves the beep's own From ("pbx" — not a registered
	// extension) and answers the phone that just started ringing with a stray
	// 404 Not Found.
	// Issue #164: a response to OUR trunk INVITE belongs to SipTrunk's dialog
	// machine, not to any session branch below -- the trunk leg is a
	// server-originated UAC with no handset Session of its own, so those
	// branches could not claim it anyway. Same intercept position as the
	// beeper's, for the same reason.
	if (_sipTrunk.handleResponse(data)) return;

	if (_beeper.ownsCallID(data->getCallID()))
	{
		return;
	}

	// The MoH preview is the same shape as the beep -- server-originated UAC, no
	// Session, From "moh" matching no registered extension -- so it needs the
	// same claim for the same reason, and a 180 is likewise provisional: the
	// preview dialog stays live until the 200 OK (handleMohPreviewOk) or a final
	// failure. Without this the phone got a 404 while it was still ringing.
	if (mohPreviewOwnsCallID(data->getCallID()))
	{
		return;
	}

	auto session = getSession(data->getCallID());
	if (session.has_value() && session.value()->isBroadcast())
	{
		return;
	}
	// Inbound anchor leg: the server is the UAC, so the handset's 180 is a
	// provisional to US — there is no upstream caller to relay it to (the
	// upstream leg already hears its own ringback). Swallow it; forwarding it
	// would echo a 180 back at the handset that just started ringing.
	if (session.has_value() && session.value()->isAnchorInbound())
	{
		return;
	}
	// Blind-transfer leg (issue #197): the server is the UAC, so the target's 180
	// is a provisional to US. There is nobody to relay it to — the transferee is
	// still on its own dialog, mid-call, and a 180 stamped with this leg's Call-ID
	// and tags matches nothing it holds. Swallow it. (A 180 takes no ACK, RFC 3261
	// §17.1.1, so unlike the final responses there is nothing else owed here.)
	if (session.has_value() && session.value()->isBlindXferLeg())
	{
		return;
	}
	endHandle(data->getFromNumber(), data);
}

void RequestsHandler::onBusy(std::shared_ptr<SipMessage> data)
{
	// The phone declined our register-beep INVITE with 486 (drawbridge #178).
	// Same claim onFinalFailure() makes, for the same reason: 486 has its own
	// handlerKey in handle()'s dispatch switch and so never reaches that
	// catch-all. handleInviteFailure() ACKs it in the INVITE transaction (RFC
	// 3261 §17.1.1.3) and frees the beep slot; without this the 486 fell through
	// to endHandle(data->getFromNumber(), ...) at the bottom of this function,
	// where the beep's own From ("pbx") matches no registered client and the
	// else branch answered the declining phone with a 404 Not Found.
	//
	// Ahead of every session branch below on purpose: a beep dialog is a
	// server-originated UAC with NO Session, so those branches could not claim
	// it anyway, and the ordering matches drawbridge's onBusy().
	// Issue #164: a response to OUR trunk INVITE belongs to SipTrunk's dialog
	// machine, not to any session branch below -- the trunk leg is a
	// server-originated UAC with no handset Session of its own, so those
	// branches could not claim it anyway. Same intercept position as the
	// beeper's, for the same reason.
	if (_sipTrunk.handleResponse(data)) return;

	if (_beeper.handleInviteFailure(data))
	{
		return;
	}

	// The MoH preview is the same kind of dialog and needs the same claim.
	if (handleMohPreviewFailure(data))
	{
		return;
	}

	// Both claims must run: they match different Call-IDs, so neither can
	// mask the other, and dropping either sends its dialog back through
	// endHandle() -- whose lookup of a server-owned From matches no
	// registered client, so the else branch answers the phone with a stray
	// 404. MoH is first only because it reached main first.
	// A blind-transfer target refusing the INVITE the server sent on the
	// transferee's behalf (issue #197). Claimed here, ahead of every session
	// branch, for the same reason a beep dialog is: the server is that leg's UAC,
	// so the ACK is ours (RFC 3261 §17.1.1.3), and nothing further down reads the
	// response as what it actually is — onBusy()'s CFB lookup used to read
	// data->getFromNumber() here, which on this leg is the TRANSFEREE, not the
	// busy party; fixed to data->getToNumber() by #256. This intercept still
	// stands regardless, for the ACK-ownership reason above.
	if (handleBlindXferFailure(data))
	{
		return;
	}

	auto session = getSession(data->getCallID());
	if (session.has_value() && session.value()->isBroadcast())
	{
		// Hunt group: a busy member means advance to the next one (the timer is
		// disarmed inside huntRingNext). If the list is exhausted, fail to caller.
		if (session.value()->isHunt())
		{
			if (session.value()->getState() == Session::State::Invited && !_forker.huntRingNext(session.value()))
			{
				endHandle(session.value()->getSrc()->getNumber(), data);
				endCall(data->getCallID(), session.value()->getSrc()->getNumber(),
					session.value()->getGroupExt(), "hunt group exhausted (busy)");
			}
			return;
		}

		session.value()->removePendingTarget(std::string(data->getFromNumber()));
		if (session.value()->getPendingTargets().empty() && session.value()->getState() == Session::State::Invited)
		{
			endHandle(session.value()->getSrc()->getNumber(), data);
			endCall(data->getCallID(), session.value()->getSrc()->getNumber(), "999", "all targets busy");
		}
		return;
	}

	// Inbound anchor ring-all: one forked extension is busy. ACK its 486 and drop
	// it from the ring set (NOT a per-extension call-forward — the anchor call
	// rings the others). Fail the whole inbound call only if this was the last
	// ringing leg and none answered.
	if (session.has_value() && session.value()->isAnchorInbound())
	{
		auto s = session.value();
		ackInboundFinal(s, data);
		if (s->getState() != Session::State::Connected)
		{
			s->removePendingTarget(std::string(data->getToNumber()));
			if (s->getPendingTargets().empty())
			{
				asyncDropCall(s->getAnchorParticipantId());
				s->setAnchorLegReleased();   // #379: endCall() must not drop it again
				endCall(std::string(data->getCallID()), s->getAnchorParticipantId(), "",
					"inbound all busy/declined");
			}
		}
		return;
	}

	// Call Forward Busy (CFB): if the busy callee has an on-busy forward target,
	// swallow the 486 and redirect the call there instead of failing the caller.
	if (session.has_value())
	{
		// Issue #256: a 486 mirrors the ORIGINAL INVITE's From/To (RFC 3261),
		// so for an ordinary proxied call data->getFromNumber() names the
		// CALLER, not the busy callee -- data->getToNumber() is the actual
		// busy party. (The blind-transfer leg above returns before reaching
		// here, so this does not need to special-case that shape: getToNumber()
		// also names the actual busy party on that leg, it just never gets here.)
		std::string busyExt(data->getToNumber());
		std::string cfb = _cfg.getForwardTarget(busyExt, "busy");
		if (!cfb.empty() && cfb != busyExt)
		{
			auto inviteMsg = session.value()->getInviteMessage();
			auto src = session.value()->getSrc();
			if (inviteMsg && src)
			{
				queueLog("CFB: " + busyExt + " busy, forwarding -> " + cfb);
				std::string callID(data->getCallID());
				// Tear down the busy leg's session, then start a fresh leg to the
				// forward target reusing the retained original INVITE.
				endCall(callID, src->getNumber(), busyExt, "forwarded on busy");
				if (_forker.redirectInvite(inviteMsg, src, cfb))
				{
					return;
				}
			}
		}
		// Issue #246: no explicit CFB target, but this extension has
		// voicemail enabled -- answer locally instead of just failing with
		// the 486 below. Unlike CFNA there is no "still ringing" leg to
		// CANCEL here (the callee already answered with 486 Busy, a final
		// response the caller's UA has already processed), so no
		// forked-dialog hazard applies -- straight to answerVoicemailDeposit().
		else if (cfb.empty() && _cfg.isVoicemailEnabled(busyExt))
		{
			auto inviteMsg = session.value()->getInviteMessage();
			auto src = session.value()->getSrc();
			if (inviteMsg && src)
			{
				// Same double-CDR shape as the CFNA divert's endCall() call --
				// see its comment. Matches the existing CFNA redirect
				// precedent, not a new problem introduced here.
				std::string callID(data->getCallID());
				endCall(callID, src->getNumber(), busyExt, "busy (voicemail)");
				answerVoicemailDeposit(inviteMsg, src, busyExt);
				return;
			}
		}
	}

	setCallState(data->getCallID(), Session::State::Busy);
	endHandle(data->getFromNumber(), data);
}

void RequestsHandler::onUnavailable(std::shared_ptr<SipMessage> data)
{
	// The phone answered our register-beep INVITE with 480 — DND, or simply not
	// willing to auto-answer right now (drawbridge #178). Identical treatment to
	// the 486 path in onBusy(): ACK it inside the INVITE transaction (RFC 3261
	// §17.1.1.3) and free the slot, rather than fall through to endHandle() and
	// mint a stray 404 at the phone off the beep's own "pbx" From.
	// Issue #164: a response to OUR trunk INVITE belongs to SipTrunk's dialog
	// machine, not to any session branch below -- the trunk leg is a
	// server-originated UAC with no handset Session of its own, so those
	// branches could not claim it anyway. Same intercept position as the
	// beeper's, for the same reason.
	if (_sipTrunk.handleResponse(data)) return;

	if (_beeper.handleInviteFailure(data))
	{
		return;
	}

	// The MoH preview is the same kind of dialog and needs the same claim.
	if (handleMohPreviewFailure(data))
	{
		return;
	}

	// Both claims must run: they match different Call-IDs, so neither can
	// mask the other, and dropping either sends its dialog back through
	// endHandle() -- whose lookup of a server-owned From matches no
	// registered client, so the else branch answers the phone with a stray
	// 404. MoH is first only because it reached main first.
	// A blind-transfer target refusing the INVITE the server sent on the
	// transferee's behalf (issue #197). Claimed here, ahead of every session
	// branch, for the same reason a beep dialog is: the server is that leg's UAC,
	// so the ACK is ours (RFC 3261 §17.1.1.3), and nothing further down reads the
	// response as what it actually is — onBusy()'s CFB lookup used to read
	// data->getFromNumber() here, which on this leg is the TRANSFEREE, not the
	// busy party; fixed to data->getToNumber() by #256. This intercept still
	// stands regardless, for the ACK-ownership reason above.
	if (handleBlindXferFailure(data))
	{
		return;
	}

	auto session = getSession(data->getCallID());
	if (session.has_value() && session.value()->isBroadcast())
	{
		// Hunt group: treat unavailable like busy — advance to the next member.
		if (session.value()->isHunt())
		{
			if (session.value()->getState() == Session::State::Invited && !_forker.huntRingNext(session.value()))
			{
				endHandle(session.value()->getSrc()->getNumber(), data);
				endCall(data->getCallID(), session.value()->getSrc()->getNumber(),
					session.value()->getGroupExt(), "hunt group exhausted (unavailable)");
			}
			return;
		}

		session.value()->removePendingTarget(std::string(data->getFromNumber()));
		if (session.value()->getPendingTargets().empty() && session.value()->getState() == Session::State::Invited)
		{
			endHandle(session.value()->getSrc()->getNumber(), data);
			endCall(data->getCallID(), session.value()->getSrc()->getNumber(), "999", "all targets unavailable");
		}
		return;
	}
	// Inbound anchor ring-all: one forked extension is unavailable (DND / out of
	// range). ACK its 480 and drop it from the ring set; fail the whole inbound
	// call only if it was the last ringing leg and none answered.
	if (session.has_value() && session.value()->isAnchorInbound())
	{
		auto s = session.value();
		ackInboundFinal(s, data);
		if (s->getState() != Session::State::Connected)
		{
			s->removePendingTarget(std::string(data->getToNumber()));
			if (s->getPendingTargets().empty())
			{
				asyncDropCall(s->getAnchorParticipantId());
				s->setAnchorLegReleased();   // #379: endCall() must not drop it again
				endCall(std::string(data->getCallID()), s->getAnchorParticipantId(), "",
					"inbound all unavailable");
			}
		}
		return;
	}
	setCallState(data->getCallID(), Session::State::Unavailable);
	endHandle(data->getFromNumber(), data);
}

void RequestsHandler::onBye(std::shared_ptr<SipMessage> data)
{
	// MoH preview hangup. Server-originated dialog with no Session, so it must be
	// claimed by Call-ID before the lookup below — otherwise the BYE falls through
	// to the unknown-dialog path and the listener is never released, leaving the
	// clip streaming at a phone that has hung up.
	if (handleMohPreviewEnd(data))
	{
		if (auto response = getMessageFromPool(*data))
		{
			response->setHeader(SipMessageTypes::OK);
			response->setVia(sipwire::viaWithReceived(data->getVia(), data->getSource()));
			_outbox.emplace_back(data->getSource(), std::move(response));
		}
		return;
	}

	// Issue #164: the CARRIER hanging up its own trunk dialog. Claimed before
	// the session lookup and before the forged-teardown check below, because
	// neither applies: a trunk dialog has no handset Session under this
	// Call-ID, and the carrier is not a registered client, so
	// isDialogSourceAuthorized() has no leg IP to match it against. SipTrunk
	// recognises it by the trunk's own Call-ID (#386), runs its OWN
	// forged-teardown check against the carrier's address and dialog tags
	// (#356), answers 200 or 403, and on a 200 calls back into
	// onTrunkRemoteBye() to BYE the handset side.
	if (_sipTrunk.handleBye(data)) return;

	auto session = getSession(data->getCallID());
	std::string destNumber(data->getToNumber());

	// Issue #164: the HANDSET hanging up a trunk call. Keyed on the session
	// flag rather than the dialled number -- by now that is a PSTN string with
	// nothing to distinguish it. Answer the phone, then let endCall() do the
	// rest: it is the ONE place the carrier BYE is sent and the relay pair is
	// released, so every other teardown path (CANCEL, forceDisconnect, the
	// sweeps) gets the same treatment without repeating it here. That is the
	// #246 lesson, applied rather than relearned.
	if (session.has_value() && session.value()->isTrunk())
	{
		if (auto response = getMessageFromPool(*data))
		{
			response->setHeader(SipMessageTypes::OK);
			response->clearBody();
			response->setVia(sipwire::viaWithReceived(data->getVia(), data->getSource()));
			_outbox.emplace_back(data->getSource(), std::move(response));
		}
		endCall(data->getCallID(), data->getFromNumber(), destNumber, "handset hung up");
		return;
	}

	// Issue #46: reject an off-path forged teardown. A BYE for an established
	// two-phone dialog must originate from one of the call's leg IPs.
	if (session.has_value() &&
		!isDialogSourceAuthorized(session.value(), data->getSource()))
	{
		queueLog("BYE for Call-ID " + std::string(data->getCallID()) +
			" rejected: source not a dialog leg (spoofed teardown)", true);
		_registrar.sendForbidden(data, "Forbidden");
		return;
	}

	if (destNumber == "777")
	{
		auto response = getMessageFromPool(*data);
		if (!response) return;   // pool exhausted: drop, peer retransmits (#101A)
		response->setHeader(SipMessageTypes::OK);
		response->setVia(sipwire::viaWithReceived(data->getVia(), data->getSource()));
		_outbox.emplace_back(data->getSource(), std::move(response));
		endCall(data->getCallID(), data->getFromNumber(), destNumber);
		return;
	}

	if (destNumber == "440")
	{
		// Media beachhead teardown: stop the RTP tone stream (only if it owns this
		// Call-ID), 200 OK the BYE, and end the session. Stream stop is idempotent.
		_rtpSender.stop(std::string(data->getCallID()));
		auto response = getMessageFromPool(*data);
		if (!response) return;   // pool exhausted: drop, peer retransmits (#101A)
		response->setHeader(SipMessageTypes::OK);
		response->setVia(sipwire::viaWithReceived(data->getVia(), data->getSource()));
		_outbox.emplace_back(data->getSource(), std::move(response));
		endCall(data->getCallID(), data->getFromNumber(), destNumber);
		return;
	}

	if (destNumber == ConferenceRoom::EXT)
	{
		// Conference hang-up: 200 OK the BYE and end the call. endCall() releases the
		// MixBus port (Active -> Draining); the remaining legs keep mixing untouched.
		auto response = getMessageFromPool(*data);
		if (!response) return;   // pool exhausted: drop, peer retransmits (#101A)
		response->setHeader(SipMessageTypes::OK);
		response->setVia(sipwire::viaWithReceived(data->getVia(), data->getSource()));
		_outbox.emplace_back(data->getSource(), std::move(response));
		endCall(data->getCallID(), data->getFromNumber(), destNumber);
		return;
	}

	// See onCancel()'s matching comment: a Trunk-routed anchor call's BYE remote
	// target is the dialed digits (buildOkWithSdp's Contact uses getToNumber()),
	// not the literal 555 code, so recognize the session by isAnchor() too.
	if (destNumber == kAnchorCallExt ||
		(session.has_value() && session.value()->isAnchor() && !session.value()->isAnchorInbound()))
	{
		// Anchor-bridge hang-up: 200 OK the BYE and end the call. endCall() (below)
		// best-effort drops the anchor-side leg and releases the MediaBridge.
		auto response = getMessageFromPool(*data);
		if (!response) return;   // pool exhausted: drop, peer retransmits (#101A)
		response->setHeader(SipMessageTypes::OK);
		response->setVia(sipwire::viaWithReceived(data->getVia(), data->getSource()));
		_outbox.emplace_back(data->getSource(), std::move(response));
		endCall(data->getCallID(), data->getFromNumber(), destNumber);
		return;
	}

	// Issue #246: a voicemail leg is locally terminated, same as 777/440/888/
	// anchor above -- but keyed on the session flag, not destNumber, since
	// destNumber here is the mailbox owner's REAL extension (whatever the
	// caller originally dialed), not a fixed virtual code (Session.hpp's own
	// isAnchor() comment warns against matching on "dest is a non-pool
	// client" or the dest's name for exactly this reason). Without this
	// branch the BYE falls through to the generic two-real-phone path at the
	// bottom of this function, which RELAYS it toward the mailbox owner's own
	// extension instead of the server answering it -- the depositor never
	// gets their 200 OK (the #232 class of bug). The leg itself is released
	// by endCall() below (its own voicemail safety net), not here directly --
	// same reasoning as the conference/anchor-bridge cleanup already living
	// there: every teardown path funnels through endCall(), not just BYE.
	if (session.has_value() && session.value()->isVoicemail())
	{
		auto response = getMessageFromPool(*data);
		if (!response) return;   // pool exhausted: drop, peer retransmits (#101A)
		response->setHeader(SipMessageTypes::OK);
		response->setVia(sipwire::viaWithReceived(data->getVia(), data->getSource()));
		_outbox.emplace_back(data->getSource(), std::move(response));
		endCall(data->getCallID(), data->getFromNumber(), destNumber, "voicemail depositor hung up");
		return;
	}

	if (destNumber == "999" || _cfg.isPageZoneDialog(destNumber))
	{
		auto response = getMessageFromPool(*data);
		if (!response) return;   // pool exhausted: drop, peer retransmits (#101A)
		response->setHeader(SipMessageTypes::OK);
		std::string activeIp = _localIp;
		response->setVia(sipwire::viaWithReceived(data->getVia(), data->getSource()));
		_outbox.emplace_back(data->getSource(), std::move(response));

		if (session.has_value())
		{
			auto answeringClient = session.value()->getDest();
			if (answeringClient)
			{
				// NOT a `return` on refusal: the caller's 200 OK is already queued
				// above, so it has its final response and will never retransmit this
				// BYE. Bailing here would skip endCall() below and leak the session
				// with no CDR. Losing the fork only leaves the paged phone to time
				// out its own dialog; losing the teardown is unrecoverable (#101A).
				auto byeFork = getMessageFromPool(*data);
				if (byeFork)
				{
				std::string serverIpPort = activeIp + ":" + std::to_string(_serverPort);
				std::string targetIpPort = sipwire::addrToIpPort(answeringClient->getAddress());

				byeFork->setHeader("BYE sip:" + answeringClient->getNumber() + "@" + targetIpPort + " SIP/2.0");

				std::string originalTo(data->getTo());
				std::string newTo = "To: <sip:" + answeringClient->getNumber() + "@" + serverIpPort + ">";
				siphdr::appendTagFrom(newTo, originalTo);
				byeFork->setTo(newTo);

				_outbox.emplace_back(answeringClient->getAddress(), std::move(byeFork));
				}
			}
		}
		endCall(data->getCallID(), data->getFromNumber(), destNumber);
		return;
	}

	// Attended-transfer bridge teardown (issue #131). MUST run before the generic
	// peerCallID branch below: after onRefer()'s splice, both the B and C sessions
	// still have src/dest exactly as they were in their ORIGINAL (pre-splice)
	// dialog with A — the generic branch below BYEs peer->getSrc(), which is
	// only ever right by coincidence here (A could be either side), so this gets
	// its own branch rather than a special case bolted onto the generic one.
	if (session.has_value() && session.value()->isTransferBridge() &&
		!session.value()->getPeerCallID().empty())
	{
		auto response = getMessageFromPool(*data);
		if (response)
		{
			response->setHeader(SipMessageTypes::OK);
			response->setVia(sipwire::viaWithReceived(data->getVia(), data->getSource()));
			response->clearBody();
			_outbox.emplace_back(data->getSource(), std::move(response));
		}

		// Issue #197: only the party still ON this dialog can tear the bridge down.
		// Both transfer paths drop a transferor whose phone may well hang up its own
		// leg rather than wait for the server's BYE (RFC 5589 §6.1 — Yealink and
		// friends do exactly this, right after the sipfrag NOTIFY), so that BYE
		// crosses ours on the wire and arrives on a dialog the server has already
		// re-purposed. Relaying it would tear down the very bridge the transfer just
		// built, a beat after the two survivors were connected. The survivor is
		// whichever side the transferor was not — the same wasTransferorSrc() the
		// relay below uses to pick it.
		{
			auto mine = session.value()->wasTransferorSrc() ? session.value()->getDest()
				: session.value()->getSrc();
			if (!mine || !sameAddress(data->getSource(), mine->getAddress()))
			{
				queueLog("BYE on a transfer bridge from the dropped transferor — "
					"answered, bridge left up", false);
				return;   // already 200 OK'd above
			}
		}

		const std::string peerId = session.value()->getPeerCallID();
		if (auto peer = getSession(peerId); peer.has_value())
		{
			auto peerSess = peer.value();
			// wasTransferorSrc() records which side A was in the PEER's original
			// dialog (captured at splice time, since A's identity is otherwise
			// gone from both sessions by now) -- the surviving party is whichever
			// side A wasn't.
			bool peerAIsSrc = peerSess->wasTransferorSrc();
			auto survivor = peerAIsSrc ? peerSess->getDest() : peerSess->getSrc();
			// Issue #197: a blind-transfer target can still be RINGING when the
			// transferee gives up and hangs up. There is no dialog to BYE yet — the
			// target has sent no To-tag — so the right teardown is a CANCEL of the
			// INVITE the server still has outstanding (RFC 3261 §9.1), reusing that
			// INVITE's own branch, which is why the leg keeps it. Without this the
			// target rings on after everyone else has gone.
			if (peerSess->isBlindXferLeg() && peerSess->getState() != Session::State::Connected)
			{
				if (auto inv = peerSess->getInviteMessage(); inv && survivor)
				{
					if (auto cancel = _forker.buildCancel(inv, survivor))
					{
						_outbox.emplace_back(survivor->getAddress(), std::move(cancel));
					}
				}
				endCall(peerId, survivor ? survivor->getNumber() : std::string(),
					std::string(data->getFromNumber()), "transfer target cancelled (transferee hung up)");
				endCall(data->getCallID(), data->getFromNumber(), destNumber, "transfer bridge BYE");
				return;
			}
			// Same #72 malformed-BYE guard as the generic branch below.
			if (survivor && !peerSess->getDialogFrom().empty() && !peerSess->getDialogTo().empty())
			{
				// Impersonate the dropped transferor (A) in the peer dialog — A's
				// own From/To tags are exactly what that phone's dialog expects.
				const std::string& peerAHdr     = peerAIsSrc ? peerSess->getDialogFrom() : peerSess->getDialogTo();
				const std::string& peerOtherHdr = peerAIsSrc ? peerSess->getDialogTo()   : peerSess->getDialogFrom();
				// #402: above everything this dialog has carried -- including the
				// splice re-INVITE the server already sent here in A's name.
				auto bye = buildServerBye(survivor->getNumber(), survivor->getAddress(),
					peerId, peerAHdr, peerOtherHdr, peerSess->nextServerCSeq());
				if (bye) _outbox.emplace_back(survivor->getAddress(), std::move(bye));
			}
			endCall(peerId, survivor ? survivor->getNumber() : std::string(),
				std::string(data->getFromNumber()), "transfer bridge peer BYE");
		}
		endCall(data->getCallID(), data->getFromNumber(), destNumber, "transfer bridge BYE");
		return;
	}

	// Cross-dialog bridge teardown (Issue #68 call pickup and, since #127,
	// ParkOrbit's park+retrieve legs — both set peerCallID AND capture dialog
	// headers). A BYE here ends ONE of two independently-dialogued legs that
	// only the server's own bookkeeping links together; relaying the raw BYE
	// as-is (its own Call-ID) would be rejected 481 by the peer's phone
	// (wrong dialog), so a peer-addressed BYE has to be built fresh from the
	// PEER session's own dialog identifiers — exactly what sweepSessionTimers()
	// already does for a single session's own two legs, generalized here
	// across two sessions.
	if (session.has_value() && !session.value()->getPeerCallID().empty())
	{
		std::string peerCallId = session.value()->getPeerCallID();
		if (auto peerSession = getSession(peerCallId); peerSession.has_value())
		{
			auto peer = peerSession.value();
			// Issue #72's guard, reused: a BYE with an empty From or To is
			// malformed and phones drop it. CallPickup::complete() and
			// ParkOrbit's park+retrieve paths always capture both via
			// setDialogHeaders() (see ParkOrbit::onInvite). ParkOrbit's
			// ring-back-timeout leg (isParkUac()) is the one path that still
			// doesn't — it's a server-initiated (UAC-role) dialog, so its
			// From/To would need swapped capture, not just the same call —
			// left as-is: a ring-back leg still gets the endCall() cleanup
			// below, just not a peer-phone BYE, rather than a malformed one.
			if (auto notify = peer->getSrc();
				notify && !peer->getDialogFrom().empty() && !peer->getDialogTo().empty())
			{
				// #389: a retrieved park leg has already had the server's re-INVITE
				// on this dialog, so the BYE must go above that CSeq, not reuse it.
				auto bye = buildServerBye(notify->getNumber(), notify->getAddress(),
					peerCallId, peer->getDialogTo(), peer->getDialogFrom(), peer->nextServerCSeq());
				if (bye) _outbox.emplace_back(notify->getAddress(), std::move(bye));
			}
			endCall(peerCallId, peer->getSrc() ? peer->getSrc()->getNumber() : "",
				peer->getDest() ? peer->getDest()->getNumber() : "", "peer leg ended (bridged call)");
		}

		auto response = getMessageFromPool(*data);
		if (response)
		{
			response->setHeader(SipMessageTypes::OK);
			response->setVia(sipwire::viaWithReceived(data->getVia(), data->getSource()));
			response->clearBody();
			_outbox.emplace_back(data->getSource(), std::move(response));
		}
		endCall(data->getCallID(), data->getFromNumber(), data->getToNumber(), "bridged call ended");
		return;
	}

	setCallState(data->getCallID(), Session::State::Bye);
	endHandle(data->getToNumber(), data);
}

void RequestsHandler::onOk(std::shared_ptr<SipMessage> data)
{
	if (data->getCSeq().find("OPTIONS") != std::string::npos)
	{
		return;
	}

	// Register-beep dialog (server-originated UAC, no Session): recognised by
	// Call-ID before the normal session lookup. handleOk drives ACK→BYE→free.
	// Issue #164: a response to OUR trunk INVITE belongs to SipTrunk's dialog
	// machine, not to any session branch below -- the trunk leg is a
	// server-originated UAC with no handset Session of its own, so those
	// branches could not claim it anyway. Same intercept position as the
	// beeper's, for the same reason.
	if (_sipTrunk.handleResponse(data)) return;

	if (_beeper.handleOk(data))
	{
		return;
	}

	// Park dialogs (server-originated re-INVITE ACKs + ring-back answers). The
	// snapshot mirror is driven by _park.consumeParkChanged() in handle(), so a
	// state-neutral ACK confirmation no longer pays a rebuild.
	if (_park.handleOk(data))
	{
		return;
	}

	// MoH preview (server-originated UAC, no Session), same intercept-by-Call-ID
	// shape as the two above. The phone answering our INVITE is what starts the
	// music, so this must run before the session lookup that would 404 it.
	if (handleMohPreviewOk(data))
	{
		return;
	}

	// Attended-transfer splice re-INVITE ACKs (issue #131), same intercept-before-
	// session-lookup pattern -- must never reach the generic relay below, which
	// would forward this 200 OK toward A, the transferor the splice already drops.
	if (handleTransferOk(data))
	{
		return;
	}

	// Blind-transfer target answered (issue #197). Same intercept-before-the-
	// session-lookup placement, and the same reason as the line above: the server
	// is the UAC on that leg, so this 200 OK is ours to ACK and to turn into the
	// transferee's re-INVITE. The generic relay below would instead forward it to
	// the leg's src — the transferee — inside a dialog it has never seen.
	if (handleBlindXferOk(data))
	{
		return;
	}
	auto session = getSession(data->getCallID());
	if (session.has_value())
	{
		// Inbound anchor leg: the server is the UAC (it originated the forked
		// INVITEs), so a 200 OK to one of them is the handset ANSWERING — drive the
		// media bridge + ACK + upstream answerCall() here, never the generic relay
		// below (which assumes the opposite: the handset is the caller). Checked
		// before the Cancel-state early return too, mirroring drawbridge exactly,
		// though an inbound-anchor session's state never actually becomes Cancel.
		if (session.value()->isAnchorInbound() &&
		    data->getCSeq().find(SipMessageTypes::INVITE) != std::string::npos)
		{
			onInboundAnchorOk(data, session.value());
			return;
		}

		if (session.value()->getState() == Session::State::Cancel)
		{
			endHandle(data->getFromNumber(), data);
			return;
		}

		// Re-INVITE answer (hold/resume): relay 200 OK to the opposite leg and
		// preserve the session state set by onReinvite() — do NOT re-run connect.
		// Applies equally to a broadcast/ring-group session once it is
		// Connected or Held (#74): after the first-answer connect path runs,
		// getSrc()/getDest() name exactly the two live legs (original caller,
		// answering client) the same way a unicast session's do, so the same
		// source-address peer lookup relays a hold/resume 200 OK for either.
		//
		// UPDATE rides this same relay (#199 root cause 2). onUpdate() forwards an
		// SDP-bearing UPDATE to the opposite leg and relies on the peer's 200 OK
		// coming back through here — but this block used to sit INSIDE an
		// `if (CSeq contains INVITE)` gate, so a `CSeq: n UPDATE` response matched
		// nothing, fell past the Bye check at the bottom of onOk(), and was
		// silently dropped. The sender's UPDATE transaction then timed out.
		//
		// That was survivable only because nothing told phones this PBX accepts
		// UPDATE. Advertising `Allow: UPDATE` (which is what makes RFC 3311
		// reachable at all — §5.1 forbids a compliant UAC from sending UPDATE
		// otherwise) would have turned a dormant gap into an active regression on
		// exactly the well-behaved phones the header is meant to serve. Hoisting
		// the block out of the INVITE gate is behaviour-identical for INVITE — it
		// still runs after the anchor-inbound and Cancel checks and still returns
		// before the broadcast/connect path — and adds the UPDATE case.
		const bool isInviteCSeq =
			data->getCSeq().find(SipMessageTypes::INVITE) != std::string::npos;
		const bool isUpdateCSeq =
			data->getCSeq().find(SipMessageTypes::UPDATE) != std::string::npos;

		if (isInviteCSeq || isUpdateCSeq)
		{
			const auto st = session.value()->getState();
			if (st == Session::State::Connected || st == Session::State::Held)
			{
				auto legSrc  = session.value()->getSrc();
				auto legDest = session.value()->getDest();
				if (legSrc && legDest)
				{
					std::shared_ptr<SipClient> peer;
					if (sameAddress(data->getSource(), legSrc->getAddress()))
					{
						peer = legDest;
					}
					else if (sameAddress(data->getSource(), legDest->getAddress()))
					{
						if (!data->getBody().empty())
							session.value()->setRemoteSdp(std::string(data->getBody()));
						peer = legSrc;
					}
					if (peer)
					{
						_outbox.emplace_back(peer->getAddress(), data);
						return;
					}
				}
			}
		}

		if (isInviteCSeq)
		{
			if (session.value()->isBroadcast())
			{
				// Only the first answer from a pending fork (Invited state) should run
				// the connect path below. A hold/resume re-INVITE's 200 OK arrives while
				// the session is Connected or Held, which the block above already relays
				// and returns from (#74) — so only a genuine new answer from a pending
				// fork ever reaches this point (#69b).
				if (session.value()->getState() == Session::State::Invited)
				{
					auto clientOpt = findClientByAddress(data->getSource());
					if (!clientOpt.has_value())
					{
						return;
					}
					auto answeringClient = clientOpt.value();

					SipSdpMessage* sdpMessage = nullptr;
					if (data->hasSdp())
					{
						sdpMessage = static_cast<SipSdpMessage*>(data.get());
					}
					if (!sdpMessage)
					{
						queueLog("Couldn't get SDP from: " + answeringClient->getNumber() + "'s broadcast OK message.", true);
						return;
					}

					// Drawn BEFORE the session is advanced: the branch above only
					// re-enters while the state is still Invited, so refusing after
					// setState(Connected) would strand the call permanently — the
					// answering phone's 200 OK retransmit could never get back in
					// here. Acquire first, mutate second (#101A).
					auto response = getMessageFromPool(*data);
					if (!response) return;   // pool exhausted: drop, peer retransmits (#101A)

					session->get()->setDest(answeringClient);
					session->get()->setState(Session::State::Connected);
					session->get()->clearRingTimer();   // hunt answered: disarm timeout

					auto inviteMsg = session.value()->getInviteMessage();

					response->setContact(buildContact(answeringClient->getNumber()));

					if (inviteMsg)
					{
						std::string originalTo(inviteMsg->getTo());
						std::string bTo(data->getTo());
						siphdr::appendTagFrom(originalTo, bTo);
						response->setTo(originalTo);
					}

					// Relayed answer on a peer-to-peer leg: keep the callee's codec
					// pick and order (it already intersected the caller's offer),
					// dropping only what this PBX won't carry. Never the blind
					// "0 8 101" rewrite -- that advertised payloads the caller
					// never offered and broke wideband/dynamic-PT phones.
					(void)response->filterAudioCodecs(/*allowWideband=*/true);
					endHandle(session.value()->getSrc()->getNumber(), std::move(response));

					if (inviteMsg)
					{
						std::string originalCSeq(inviteMsg->getCSeq());
						size_t invitePos = originalCSeq.find("INVITE");
						if (invitePos != std::string::npos)
						{
							originalCSeq.replace(invitePos, 6, "CANCEL");
						}

						for (const auto& target : session.value()->getPendingTargets())
						{
							if (target->getNumber() != answeringClient->getNumber())
							{
								auto cancelMsg = getMessageFromPool(*inviteMsg);
								if (!cancelMsg) continue;   // pool exhausted: skip this target (#101A)
								std::string targetIpPort = sipwire::addrToIpPort(target->getAddress());

								cancelMsg->setHeader("CANCEL sip:" + target->getNumber() + "@" + targetIpPort + " SIP/2.0");
								cancelMsg->setCSeq(originalCSeq);
								_outbox.emplace_back(target->getAddress(), std::move(cancelMsg));
							}
						}
					}
				}
				return;
			}

			auto client = findClient(data->getToNumber());
			if (!client.has_value())
			{
				return;
			}

			// Issue #68 pickup race: once this session is already connected to
			// someone ELSE (a directed/group pickup answered first), a late
			// 200 OK from this call's now-superseded (CANCELed) fork must not
			// resurrect/steal the session — a CANCEL and a 2xx can legally
			// cross on the wire. Silently drop it, same treatment the
			// isBroadcast() branch above already gives a post-connect answer.
			// A genuine retransmit of the WINNING answer (dest already ==
			// this responder) still falls through to the normal path below.
			if (session.value()->getState() != Session::State::Invited &&
				!(session.value()->getDest() &&
					session.value()->getDest()->getNumber() == client.value()->getNumber()))
			{
				return;
			}

			SipSdpMessage* sdpMessage = nullptr;
			if (data->hasSdp())
			{
				sdpMessage = static_cast<SipSdpMessage*>(data.get());
			}
			if (!sdpMessage) 
			{
				queueLog("Couldn't get SDP from: " + client.value()->getNumber() + "'s OK message.", true);
				std::shared_ptr<SipMessage> responseObj = getMessageFromPool(*data);
				if (!responseObj) return;   // pool exhausted: drop, peer retransmits (#101A)
				responseObj->setHeader(SipMessageTypes::BAD_REQUEST);
				responseObj->clearBody();
				responseObj->setContact(buildContact(data->getToNumber()));
				endHandle(data->getToNumber(), responseObj);
				endCall(data->getCallID(), data->getFromNumber(), data->getToNumber(), "SDP parse error.");
				return;
			}
			session->get()->setDest(client.value());
			session->get()->setState(Session::State::Connected);
			session->get()->clearRingTimer();   // answered: disarm any CFNA timeout
			// Capture dialog From/To and callee SDP so attended transfer can
			// cross-connect two live sessions without querying stored invite messages.
			session->get()->setDialogHeaders(std::string(data->getFrom()),
			                                std::string(data->getTo()));
			session->get()->setRemoteSdp(std::string(data->getBody()));
			armSessionTimer(session->get(), data);
			auto response = getMessageFromPool(*data);
			if (!response) return;   // pool exhausted: drop, peer retransmits (#101A)
			response->setContact(buildContact(data->getToNumber()));
			endHandle(data->getFromNumber(), std::move(response));
			return;
		}

		if (session.value()->getState() == Session::State::Bye)
		{
			endHandle(data->getFromNumber(), data);
			endCall(data->getCallID(), data->getToNumber(), data->getFromNumber());
		}
	}
}

void RequestsHandler::onAck(std::shared_ptr<SipMessage> data)
{
	auto session = getSession(data->getCallID());
	if (!session.has_value())
	{
		return;
	}

	std::string destNumber(data->getToNumber());
	if (destNumber == "777")
	{
		return;
	}

	if (destNumber == ConferenceRoom::EXT)
	{
		// The server is the UAS on a conference leg (as with 777): the ACK completes
		// our own 200 OK and there is no second leg to relay it to. Media is already
		// flowing — the leg joined the bus when the INVITE was answered.
		return;
	}

	// See onCancel()'s matching comment: a Trunk-routed anchor call's ACK
	// Request-URI carries the dialed digits, not the literal 555 code, so
	// recognize the session by isAnchor() too — otherwise this ACK falls through
	// and the ring timer is never disarmed, and tick() reaps the just-answered
	// call at ANCHOR_ACK_TIMEOUT as if the handset never ACKed it.
	if (destNumber == kAnchorCallExt ||
		(session.value()->isAnchor() && !session.value()->isAnchorInbound()))
	{
		// Same as 777/888 above: the server is the UAS on an anchor-bridge leg, so
		// the ACK completes our own 200 OK with no second SIP leg to relay it to.
		// Media is already flowing — the bridge attached when the INVITE was answered.
		// A real anchor's CallEvent::Answered handler re-arms the ring timer as an
		// ACK deadline (ANCHOR_ACK_TIMEOUT) so tick() can reap an abandoned call
		// whose handset never ACKs — this genuine ACK disarms it. No-op for
		// Loopback (never armed: it answers synchronously — see onAnchorInvite()).
		// `session` is the one fetched and null-checked at the top of onAck().
		session.value()->clearRingTimer();
		return;
	}

	if (destNumber == "999")
	{
		auto answeringClient = session.value()->getDest();
		if (answeringClient)
		{
			auto ackFork = getMessageFromPool(*data);
			if (!ackFork) return;   // pool exhausted: drop, peer retransmits (#101A)
			std::string activeIp = _localIp;
			std::string serverIpPort = activeIp + ":" + std::to_string(_serverPort);
			std::string targetIpPort = sipwire::addrToIpPort(answeringClient->getAddress());

			ackFork->setHeader("ACK sip:" + answeringClient->getNumber() + "@" + targetIpPort + " SIP/2.0");

			std::string originalTo(data->getTo());
			std::string newTo = "To: <sip:" + answeringClient->getNumber() + "@" + serverIpPort + ">";
			siphdr::appendTagFrom(newTo, originalTo);
			ackFork->setTo(newTo);

			_outbox.emplace_back(answeringClient->getAddress(), std::move(ackFork));
		}
		return;
	}

	endHandle(data->getToNumber(), data);

	auto sessionState = session.value()->getState();
	std::string endReason;
	if (sessionState == Session::State::Busy)
	{
		endReason = std::string(data->getToNumber()) + " is busy.";
		endCall(data->getCallID(), data->getFromNumber(), data->getToNumber(), endReason);
		return;
	}

	if (sessionState == Session::State::Unavailable)
	{
		endReason = std::string(data->getToNumber()) + " is unavailable.";
		endCall(data->getCallID(), data->getFromNumber(), data->getToNumber(), endReason);
		return;
	}

	if (sessionState == Session::State::Cancel)
	{
		endReason = std::string(data->getFromNumber()) + " canceled the session.";
		endCall(data->getCallID(), data->getFromNumber(), data->getToNumber(), endReason);
		return;
	}
}

void RequestsHandler::onRefer(std::shared_ptr<SipMessage> data)
{
	// RFC 3515 REFER handler -- blind transfer and attended transfer (RFC 3891
	// Replaces). The transferor sends REFER with a Refer-To header naming the
	// target. When the Refer-To carries a ?Replaces=callid URI parameter, the
	// REFER is attended: two existing sessions (A-B and A-C, where A is this
	// transferor) are spliced via cross re-INVITEs so B and C talk directly once A
	// drops out (see the attended-transfer block below, issue #131). Otherwise the
	// REFER is a blind transfer: 202 Accepted, then a fresh INVITE from the
	// transferor to the target, reported back via NOTIFY (Event: refer + sipfrag).
	auto transferorOpt = findClient(data->getFromNumber());
	if (!transferorOpt.has_value())
	{
		// Unknown transferor: reject (consistent with onInvite's 403 for non-registered).
		auto response = getMessageFromPool(*data);
		if (!response) return;   // pool exhausted: drop, peer retransmits (#101A)
		response->setHeader("SIP/2.0 403 Forbidden");
		response->clearBody();
		response->setVia(sipwire::viaWithReceived(data->getVia(), data->getSource()));
		_outbox.emplace_back(data->getSource(), std::move(response));
		return;
	}
	auto transferor = transferorOpt.value();

	// Pull the Refer-To header value out of the raw message, extract the target,
	// and (issue #131) any ?Replaces= URI parameter naming the consult dialog.
	std::string target;
	std::string replacesCallIdBare; // bare call-id from ?Replaces=, URL-decoded
	// True when a Replaces= param was present but decoded to something
	// containing a control character (e.g. a %0D%0A-smuggled CRLF that would
	// otherwise be embedded verbatim into an outgoing Call-ID header below).
	// A malformed Replaces is NOT the same as an absent one -- it forces a
	// 603 Decline rather than silently downgrading to a blind transfer.
	bool replacesMalformed = false;
	{
		const std::string& raw = data->toString();
		// Case-insensitive scan for a "Refer-To:" header line (no compact form in 3515).
		size_t pos = 0;
		while (pos < raw.size())
		{
			size_t lineEnd = raw.find('\n', pos);
			size_t next = (lineEnd == std::string::npos) ? raw.size() : lineEnd + 1;
			if ((raw[pos] == 'r' || raw[pos] == 'R') && next - pos >= 9)
			{
				std::string name = raw.substr(pos, 9);
				std::transform(name.begin(), name.end(), name.begin(),
					[](unsigned char c){ return static_cast<char>(std::tolower(c)); });
				if (name == "refer-to:")
				{
					size_t valEnd = (lineEnd == std::string::npos) ? raw.size() : lineEnd;
					std::string value = raw.substr(pos + 9, valEnd - (pos + 9));
					target = pbx::parseReferToTarget(value);

					// parseReferToTarget() stops at '?', so the URI params (including
					// Replaces=) are still intact in `value`.
					if (size_t qmark = value.find('?'); qmark != std::string::npos)
					{
						std::string uriParams = value.substr(qmark + 1);
						if (size_t rp = uriParams.find("Replaces="); rp != std::string::npos)
						{
							std::string repVal = uriParams.substr(rp + 9);
							size_t semi = repVal.find_first_of(";&>\r");
							replacesCallIdBare = siphdr::urlDecode(
								(semi == std::string::npos) ? repVal : repVal.substr(0, semi));
							// URL-decode FIRST, then strip: a %3B-encoded ;from-tag=/
							// ;to-tag= param must not bleed into the bare call-id used
							// for the session lookup below.
							if (size_t semiDecoded = replacesCallIdBare.find(';');
								semiDecoded != std::string::npos)
							{
								replacesCallIdBare.resize(semiDecoded);
							}
							for (unsigned char c : replacesCallIdBare)
							{
								if (c < 0x20 || c == 0x7F)
								{
									replacesMalformed = true;
									break;
								}
							}
						}
					}
					break;
				}
			}
			else if (raw[pos] == '\r' || raw[pos] == '\n')
			{
				break; // header/body boundary
			}
			pos = next;
		}
	}

	if (target.empty() || !isValidAor(target))
	{
		auto response = getMessageFromPool(*data);
		if (!response) return;   // pool exhausted: drop, peer retransmits (#101A)
		response->setHeader(SipMessageTypes::BAD_REQUEST);
		response->clearBody();
		response->setVia(sipwire::viaWithReceived(data->getVia(), data->getSource()));
		_outbox.emplace_back(data->getSource(), std::move(response));
		return;
	}

	std::string callID(data->getCallID());

	// Issue #133: reject an off-path forged transfer, the REFER analogue of #46's
	// BYE guard. findClient() above only proves the From header names a REGISTERed
	// extension — From is attacker-chosen, so on its own it lets any registered
	// phone name someone else's Call-ID and tear that session down (blind path:
	// endCall() + a BYE to the victim's peer) or splice it into another dialog
	// (attended path). Same rule as onBye: an in-dialog REFER must arrive from one
	// of the dialog's own leg IPs. isDialogSourceAuthorized() fails open on an
	// unknown or half-set-up session, so a genuinely out-of-dialog REFER still
	// falls through to the blind-transfer path exactly as before.
	if (auto referred = getSession(callID); referred.has_value() &&
		!isDialogSourceAuthorized(referred.value(), data->getSource()))
	{
		queueLog("REFER for Call-ID " + callID +
			" rejected: source not a dialog leg (spoofed transfer)", true);
		_registrar.sendForbidden(data, "Forbidden");
		return;
	}

	// The consult dialog gets the same treatment. The attended block below only
	// checks that the transferor's NUMBER is common to both dialogs — also a
	// From-header claim — so without this a party legitimately on the A-B dialog
	// could still name any unrelated call A happens to be in as ?Replaces= and
	// splice A out of it. A real transferor is a leg of both dialogs and passes
	// both checks; anyone else fails one.
	if (!replacesCallIdBare.empty())
	{
		if (auto consult = getSession("Call-ID: " + replacesCallIdBare);
			consult.has_value() &&
			!isDialogSourceAuthorized(consult.value(), data->getSource()))
		{
			queueLog("REFER Replaces=" + replacesCallIdBare +
				" rejected: source not a leg of the consult dialog (spoofed transfer)", true);
			_registrar.sendForbidden(data, "Forbidden");
			return;
		}
	}

	// ── Attended transfer (RFC 3891 Replaces), issue #131 ─────────────────────────
	// A (transferor) has two active calls: A-B (this REFER's own dialog, callID)
	// and A-C (the consult session, replacesCallIdBare). Splice B<->C via cross
	// re-INVITEs carrying swapped SDP, then drop A from both dialogs. Falls through
	// to the blind-transfer path below when Replaces is absent (or unusable).
	if (!replacesCallIdBare.empty() || replacesMalformed)
	{
		const std::string replacesCallIdKey = "Call-ID: " + replacesCallIdBare;
		bool canSplice = false;
		std::shared_ptr<Session> ab, ac;
		std::shared_ptr<SipClient> bClient, cClient;
		std::string bSdp, cSdp, dFromAB, dToAB, dFromAC, dToAC;
		bool aIsSrcAB = false, aIsSrcAC = false;

		if (replacesMalformed)
		{
			// A control character survived decode (e.g. a %0D%0A-smuggled CRLF) --
			// refuse outright rather than looking anything up with it. Decline,
			// don't silently fall through to blind transfer: the caller asked for
			// an attended transfer and it should fail as one, not quietly change
			// what it did.
			queueLog("REFER: attended transfer Replaces contains a control character after decode, declining", true);
		}
		else
		{
			auto sessionAB = getSession(callID);
			auto sessionAC = getSession(replacesCallIdKey);
			canSplice = sessionAB.has_value() && sessionAC.has_value();
			if (canSplice)
			{
				ab = sessionAB.value();
				ac = sessionAC.value();
				const std::string aNum = transferor->getNumber();
				aIsSrcAB = ab->getSrc() && ab->getSrc()->getNumber() == aNum;
				bool aIsDestAB = ab->getDest() && ab->getDest()->getNumber() == aNum;
				aIsSrcAC = ac->getSrc() && ac->getSrc()->getNumber() == aNum;
				bool aIsDestAC = ac->getDest() && ac->getDest()->getNumber() == aNum;
				// A coherence check, not an auth check (#133's source gate above is
				// the auth one): A must be common to BOTH dialogs, or there is nothing
				// to splice. Kept even though the source gate now subsumes the
				// spoofing case — it still catches an honest client's mismatched pair.
				if (!(aIsSrcAB || aIsDestAB) || !(aIsSrcAC || aIsDestAC))
				{
					queueLog("REFER: attended transfer invariant violated (A not common to both dialogs)", true);
					canSplice = false;
				}
				// Stage B of the TelephonyAnchorClient port added isAnchor()/
				// isAnchorInbound() to Session -- decline splicing either dialog if
				// one is an anchor leg. Their "SDP" isn't a real peer offer/answer to
				// swap (outbound: a virtual peer standing in for the upstream anchor;
				// inbound: the MediaBridge, not a second SIP dialog, carries the
				// audio), so bClient/cClient/bSdp/cSdp below would be meaningless for
				// that side.
				if (canSplice && (ab->isAnchor() || ab->isAnchorInbound() ||
				                  ac->isAnchor() || ac->isAnchorInbound()))
				{
					queueLog("REFER: attended transfer declined — anchored session", true);
					canSplice = false;
				}
			}
			if (canSplice)
			{
				// A can be EITHER side of either dialog (the receptionist case: B
				// calls A, A consults C, A transfers -- A is AB's callee, not its
				// caller), so "the other party" and their SDP must be derived from
				// which side A actually is, never assumed. getRemoteSdp() is always
				// "the callee's SDP" -- when A is the callee, that SDP is A's OWN
				// answer, not B's/C's, so the caller's original offer is read back
				// from the stored INVITE message body instead (kept for the call's
				// life -- see getInviteMessage()'s other callers). Same hold-SDP
				// staleness caveat as the getRemoteSdp() path: this can't detect a
				// later re-INVITE either, for the same reason noted below.
				bClient = aIsSrcAB ? ab->getDest() : ab->getSrc();
				cClient = aIsSrcAC ? ac->getDest() : ac->getSrc();
				bSdp = aIsSrcAB ? ab->getRemoteSdp()
					: (ab->getInviteMessage() ? std::string(ab->getInviteMessage()->getBody()) : std::string());
				cSdp = aIsSrcAC ? ac->getRemoteSdp()
					: (ac->getInviteMessage() ? std::string(ac->getInviteMessage()->getBody()) : std::string());
				dFromAB = ab->getDialogFrom(); // AB dialog's caller (src) tag -- not necessarily A's
				dToAB   = ab->getDialogTo();   // AB dialog's callee (dest) tag -- not necessarily B's
				dFromAC = ac->getDialogFrom(); // AC dialog's caller (src) tag -- not necessarily A's
				dToAC   = ac->getDialogTo();   // AC dialog's callee (dest) tag -- not necessarily C's
				if (!bClient || !cClient || bSdp.empty() || cSdp.empty() ||
					dFromAB.empty() || dToAB.empty() || dFromAC.empty() || dToAC.empty())
				{
					// SDP or dialog headers missing (call too new, or a leg never
					// reached Connected) -- nothing coherent to splice. NOTE: a phone
					// that put B on hold before consulting C has bSdp/cSdp holding B's
					// HOLD answer (a=recvonly/inactive), not a resumed one -- this
					// check doesn't (and can't, from here) catch that; it only catches
					// SDP/headers never having been captured at all.
					canSplice = false;
				}
			}
		}

		if (!canSplice)
		{
			auto declined = getMessageFromPool(*data);
			if (!declined) return;   // pool exhausted: drop, peer retransmits (#101A)
			declined->setHeader("SIP/2.0 603 Decline");
			declined->clearBody();
			declined->setVia(sipwire::viaWithReceived(data->getVia(), data->getSource()));
			_outbox.emplace_back(data->getSource(), std::move(declined));
			return;
		}

		// ── Draw every wire-critical message BEFORE mutating any session state or
		// sending anything (#101A, same acquire-everything-then-mutate discipline as
		// CallPickup::complete()). A splice touches two sessions' worth of wire state
		// (two BYEs, two re-INVITEs, one 202); a refusal partway through would leave
		// A half-dropped with B/C never re-INVITEd — worse than declining outright,
		// so on ANY refusal below nothing is sent and nothing mutates.
		const std::string srcIpPort = _localIp + ":" + std::to_string(_serverPort);

		// Issue #402 (replacing #257's per-dialog floors). invToB/invToC impersonate
		// A inside each PRE-EXISTING dialog, and the BYEs/NOTIFY below speak on them
		// too, so every one needs a CSeq above anything that dialog has already
		// carried, or the phone rejects it 500 Invalid CSeq (RFC 3261 s12.2.2).
		//
		// The old floors assumed the REFER arrives on the HELD dialog and took the
		// other one's setup-INVITE CSeq +1. A transferor may REFER on either
		// dialog (RFC 5589); pjsua REFERs on the consult one, which makes the
		// replaced dialog the held one -- and holding is a re-INVITE at exactly
		// setup+1, so the splice collided with it on every call. Each session now
		// records every CSeq either party has sent on it (handle(), which already
		// counted this REFER), so each dialog simply goes above its own record.
		// Numbers are reserved (noted) only once every draw below has succeeded.
		// Per dialog, in this order: the re-INVITE, then what goes to A (BYE, then
		// NOTIFY). Distinct recipients only need their own numbers increasing.
		const uint32_t abBase = ab->nextServerCSeq();   // invToB, byeAfromAB, NOTIFY
		const uint32_t acBase = ac->nextServerCSeq();   // invToC, byeAfromAC

		// A's own tag/header in each dialog, and the other party's -- these flip
		// with orientation. A message the server sends impersonating A carries
		// A's own tag as From and the peer's as To; a message impersonating the
		// OTHER party (toward A, e.g. the BYE below) is the reverse. Same
		// role-inversion reasoning as setParkUac()'s own comment.
		const std::string& aHdrAB     = aIsSrcAB ? dFromAB : dToAB;
		const std::string& otherHdrAB = aIsSrcAB ? dToAB   : dFromAB;
		const std::string& aHdrAC     = aIsSrcAC ? dFromAC : dToAC;
		const std::string& otherHdrAC = aIsSrcAC ? dToAC   : dFromAC;

		auto byeAfromAB = buildServerBye(transferor->getNumber(), transferor->getAddress(),
			callID, otherHdrAB, aHdrAB, abBase + 1);
		auto byeAfromAC = buildServerBye(transferor->getNumber(), transferor->getAddress(),
			replacesCallIdKey, otherHdrAC, aHdrAC, acBase + 1);

		std::shared_ptr<SipMessage> invToB;
		{
			std::ostringstream ss;
			ss << "INVITE sip:" << bClient->getNumber() << "@" << sipwire::addrToIpPort(bClient->getAddress()) << " SIP/2.0\r\n"
			   << "Via: SIP/2.0/UDP " << srcIpPort << ";branch=z9hG4bK" << IDGen::GenerateID(12) << "\r\n"
			   << "From: " << stripHeaderName(aHdrAB) << "\r\n"
			   << "To: " << stripHeaderName(otherHdrAB) << "\r\n"
			   << "Call-ID: " << stripHeaderName(callID) << "\r\n"
			   << "CSeq: " << abBase << " INVITE\r\n"
			   << "Max-Forwards: 70\r\n"
			   << "Contact: <sip:" << bClient->getNumber() << "@" << srcIpPort << ">\r\n"
			   << "User-Agent: pocket-dial\r\n"
			   << "Content-Type: application/sdp\r\n"
			   << "Content-Length: " << cSdp.size() << "\r\n\r\n"
			   << cSdp;
			invToB = getMessageFromPool(ss.str(), bClient->getAddress());
		}
		std::shared_ptr<SipMessage> invToC;
		{
			std::ostringstream ss;
			ss << "INVITE sip:" << cClient->getNumber() << "@" << sipwire::addrToIpPort(cClient->getAddress()) << " SIP/2.0\r\n"
			   << "Via: SIP/2.0/UDP " << srcIpPort << ";branch=z9hG4bK" << IDGen::GenerateID(12) << "\r\n"
			   << "From: " << stripHeaderName(aHdrAC) << "\r\n"
			   << "To: " << stripHeaderName(otherHdrAC) << "\r\n"
			   << "Call-ID: " << replacesCallIdBare << "\r\n"
			   << "CSeq: " << acBase << " INVITE\r\n"
			   << "Max-Forwards: 70\r\n"
			   << "Contact: <sip:" << cClient->getNumber() << "@" << srcIpPort << ">\r\n"
			   << "User-Agent: pocket-dial\r\n"
			   << "Content-Type: application/sdp\r\n"
			   << "Content-Length: " << bSdp.size() << "\r\n\r\n"
			   << bSdp;
			invToC = getMessageFromPool(ss.str(), cClient->getAddress());
		}
		auto accepted = getMessageFromPool(*data);

		if (!byeAfromAB || !byeAfromAC || !invToB || !invToC || !accepted)
		{
			// Pool exhausted partway through the draw: nothing has been sent or
			// mutated yet (#101A) — drop, the transferor's phone retransmits the
			// REFER and the whole splice is retried cleanly from scratch.
			return;
		}

		(void)invToB->filterAudioCodecs(/*allowWideband=*/true);   // phone SDP relayed P2P
		invToB->syncContentLength();
		(void)invToC->filterAudioCodecs(/*allowWideband=*/true);   // phone SDP relayed P2P
		invToC->syncContentLength();

		accepted->setHeader(SipMessageTypes::ACCEPTED);
		accepted->clearBody();
		accepted->setVia(sipwire::viaWithReceived(data->getVia(), data->getSource()));
		accepted->setTo(std::string(data->getTo()) + ";tag=" + IDGen::GenerateID(9));
		_outbox.emplace_back(data->getSource(), std::move(accepted));

		_outbox.emplace_back(transferor->getAddress(), std::move(byeAfromAB));
		_outbox.emplace_back(transferor->getAddress(), std::move(byeAfromAC));
		_outbox.emplace_back(bClient->getAddress(), std::move(invToB));
		_outbox.emplace_back(cClient->getAddress(), std::move(invToC));
		_transferPendingAcks.push_back(callID);
		_transferPendingAcks.push_back(replacesCallIdKey);
		ab->noteServerCSeq(abBase + 2);   // + the NOTIFY below, sent best-effort
		ac->noteServerCSeq(acBase + 1);

		// Link the two sessions as a transfer bridge: a BYE from either B or C
		// (onBye's isTransferBridge() branch) relays to the other, using
		// wasTransferorSrc() to find the surviving party -- A can be either
		// src or dest of either original dialog, so unlike the generic
		// peerCallID branch below it, this can't hardcode getDest().
		ab->setPeerCallID(replacesCallIdKey);
		ab->setTransferBridge(true);
		ab->setWasTransferorSrc(aIsSrcAB);
		ac->setPeerCallID(callID);
		ac->setTransferBridge(true);
		ac->setWasTransferorSrc(aIsSrcAC);

		// NOTIFY A with the success sipfrag — best-effort: the splice itself is
		// already fully committed and on the wire by this point, so a pool refusal
		// here just means A's phone doesn't get the courtesy status update.
		auto notify = buildReferNotify(data, transferor, "SIP/2.0 200 OK", /*terminated=*/true,
			abBase + 2);
		if (notify) _outbox.emplace_back(transferor->getAddress(), std::move(notify));

		queueLog("REFER: attended transfer " + transferor->getNumber() + " -> " +
			bClient->getNumber() + " <-> " + cClient->getNumber());
		return;
	}

	// ── Blind transfer (RFC 3515 §2, RFC 5359 §2.4) ────────────────────────────────
	// A and B are talking; A REFERs to C. The party that ends up talking to C is
	// B — the TRANSFEREE, the leg a transfer MOVES — while A, the transferor, drops
	// out. Issue #197: this handler used to do the exact opposite. It BYEd B (the
	// one party a transfer exists to keep) and re-INVITEd A to C, so a receptionist
	// transferring an inbound caller hung up on the customer and was dialled through
	// to the target themselves — with the sipfrag NOTIFY reporting 200 OK, so the
	// lost call was invisible until the customer rang back. The REFER machinery
	// around it was right; one decision about which leg survives was inverted.
	//
	// Moving B instead of A is not a swap of two arguments, because media here is
	// peer-to-peer: the board relays offers and answers and never sits in the audio
	// path, so "B ends up talking to C" means B's and C's SDP have to reach each
	// other. That makes a blind transfer a two-dialog B2BUA operation:
	//
	//   1. mint a NEW dialog toward C carrying B's media, impersonating B;
	//   2. BYE A out of the A-B dialog, which SURVIVES as B's half of the bridge;
	//   3. when C answers: ACK it, and re-INVITE B with C's SDP (handleBlindXferOk);
	//   4. link the two Call-IDs so a BYE from either party reaches the other.
	//
	// Step 3 is the same offer/answer swap ParkOrbit's retrieve performs (answer the
	// retriever with the parked party's SDP, re-INVITE the parked party with the
	// retriever's) — split across time, because C has to be rung before its answer
	// exists to swap in.
	//
	// The old "tear the leg down FIRST, then redirect" ordering (#128) is not being
	// ignored here, it no longer has anything to order: the collision it guarded
	// against was redirectInvite() reusing the A-B Session for the transfer leg
	// under the same Call-ID. The leg toward C now has its own Call-ID and its own
	// Session, and the A-B Session is deliberately KEPT (it is B's dialog, and B is
	// staying). redirectInvite() and that ordering are untouched for CFB/CFNA, which
	// still redirect the same party and therefore still need both.

	// Resolve the whole transfer before a byte moves. Issue #203's gate — the target
	// lookup decides the outcome BEFORE any teardown — is preserved and widened:
	// every ingredient (target, transferee, transferee media, message pool, session
	// pool) is checked first, and any miss declines the transfer with the call left
	// exactly as it was.
	auto targetClient = findClient(target);
	auto originalOpt = getSession(callID);

	// The transferee, and the media it is currently on. The transferor can be
	// EITHER side of the A-B dialog — the receptionist case has them as the callee
	// — so both are derived from which side the transferor actually is, never
	// assumed. getRemoteSdp() is always "the callee's SDP", so when the transferor
	// is the callee that SDP is the transferor's own answer and the transferee's
	// offer must be read back off the stored INVITE instead. Same derivation the
	// attended splice above uses, for the same reason.
	std::shared_ptr<Session> original;
	std::shared_ptr<SipClient> transferee;
	bool transferorIsSrc = false;
	std::string transfereeSdp;
	if (originalOpt.has_value())
	{
		original = originalOpt.value();
		// Issue #257. The REFER itself is a real, fresh in-dialog request from
		// the transferor (A) on this exact dialog, so its own CSeq is a directly-
		// observed floor: any later request minted here IMPERSONATING A must use
		// a higher CSeq than this, or B's dialog layer correctly rejects it with
		// 500 Invalid CSeq (RFC 3261 s12.2.2) — see handleBlindXferOk(), the only
		// reader. Recorded unconditionally, including on a REFER that ends up
		// declined below: a slightly stale-but-safe value from an earlier REFER
		// is harmless, and a later successful REFER always overwrites it with a
		// fresher one before it is ever read.
		original->setTransferorCseqAtRefer(siphdr::cseqNumber(data->getCSeq()));
		transferorIsSrc = original->getSrc() &&
			original->getSrc()->getNumber() == transferor->getNumber();
		if (auto other = transferorIsSrc ? original->getDest() : original->getSrc();
			other && other->getNumber() != transferor->getNumber())
		{
			transferee = other;
		}
		transfereeSdp = transferorIsSrc
			? original->getRemoteSdp()
			: (original->getInviteMessage()
				? std::string(original->getInviteMessage()->getBody())
				: std::string());
		// Anchored legs are declined for the same reason the attended splice
		// declines them: their "SDP" is not a peer offer/answer that a third phone
		// could be handed (outbound: a virtual peer standing in for the upstream
		// anchor; inbound: a MediaBridge, not a second SIP dialog).
		if (original->isAnchor() || original->isAnchorInbound()) transferee = nullptr;
	}

	// A REFER landing on a dialog that has ALREADY been transferred once. Two ways
	// to get here, needing opposite answers, and neither is "do it again":
	//
	//   * a retransmit, because the transferor's 202 was lost. Running the branch
	//     below a second time would invite the target twice, BYE a party that is
	//     already gone, and overwrite setPeerCallID() — orphaning the first leg,
	//     which then rings on with nothing tracking it. Re-send the 202 that went
	//     missing and stop; the transfer itself is already done.
	//   * the SURVIVOR chaining a further transfer. The derivation above cannot
	//     serve that: src/dest still name the ORIGINAL pair, so "the party that is
	//     not the transferor" resolves to the transferor already dropped, and the
	//     real far end is on the other Call-ID entirely. Declining is the honest
	//     answer — transferring the wrong party while reporting success is #197.
	if (original && original->isTransferBridge())
	{
		auto dropped = original->wasTransferorSrc() ? original->getSrc() : original->getDest();
		const bool isRetransmit = dropped && dropped->getNumber() == transferor->getNumber();
		auto response = getMessageFromPool(*data);
		if (!response) return;   // pool exhausted: drop, peer retransmits (#101A)
		response->setHeader(isRetransmit ? std::string(SipMessageTypes::ACCEPTED)
			: std::string("SIP/2.0 603 Decline"));
		response->clearBody();
		response->setVia(sipwire::viaWithReceived(data->getVia(), data->getSource()));
		if (isRetransmit)
		{
			response->setTo(std::string(data->getTo()) + ";tag=" + IDGen::GenerateID(9));
		}
		else
		{
			queueLog("REFER: transfer of an already-transferred leg declined — "
				"the far end is on another dialog", true);
		}
		_outbox.emplace_back(data->getSource(), std::move(response));
		return;
	}

	if (!transferee || transfereeSdp.empty())
	{
		// There is no leg to move. Either the REFER names no dialog this PBX knows
		// (an out-of-dialog REFER — which under the pre-#197 topology quietly became
		// click-to-dial FOR THE TRANSFEROR, not a transfer of anyone), or the dialog
		// has no second party, or no media was ever captured for it (a transfer
		// attempted before the call was answered). Decline honestly rather than do
		// something else and report it as a transfer.
		auto declined = getMessageFromPool(*data);
		if (!declined) return;   // pool exhausted: drop, peer retransmits (#101A)
		declined->setHeader(original ? "SIP/2.0 603 Decline"
			: "SIP/2.0 481 Call/Transaction Does Not Exist");
		declined->clearBody();
		declined->setVia(sipwire::viaWithReceived(data->getVia(), data->getSource()));
		_outbox.emplace_back(data->getSource(), std::move(declined));
		queueLog("REFER: blind transfer declined — no transferable leg on " + callID, true);
		return;
	}

	// 202 Accepted to the transferor (RFC 3515 §2.4.4).
	{
		auto accepted = getMessageFromPool(*data);
		if (!accepted) return;   // pool exhausted: drop, peer retransmits (#101A)
		accepted->setHeader(SipMessageTypes::ACCEPTED);
		accepted->clearBody();
		accepted->setVia(sipwire::viaWithReceived(data->getVia(), data->getSource()));
		accepted->setTo(std::string(data->getTo()) + ";tag=" + IDGen::GenerateID(9));
		_outbox.emplace_back(data->getSource(), std::move(accepted));
	}

	// Issue #203, unchanged in substance: an unresolvable target (a park orbit, a
	// typo, an extension that just dropped its registration) declines the transfer
	// and leaves the call up. It matters more now, not less — the party that used to
	// be hung up on here is the one now being kept.
	if (!targetClient.has_value())
	{
		auto notify = buildReferNotify(data, transferor, "SIP/2.0 404 Not Found", /*terminated=*/true);
		if (notify) _outbox.emplace_back(transferor->getAddress(), std::move(notify));
		queueLog("REFER: blind transfer to " + target + " declined (no such target) — "
			"call left up", true);
		return;
	}

	const std::string srcIpPort = _localIp + ":" + std::to_string(_serverPort);
	const std::string legCallID = "Call-ID: " + IDGen::GenerateID(16) + "@" + _localIp;
	const std::string legBranch = "z9hG4bK" + IDGen::GenerateID(12);
	const std::string legFromTag = IDGen::GenerateID(9);
	// The server stands in for the TRANSFEREE on the new leg, so From and Contact
	// carry the transferee's identity: the target's phone must announce the caller
	// it is about to be connected to, not the extension that pressed Transfer.
	const std::string legFrom = "<sip:" + transferee->getNumber() + "@" + srcIpPort +
		">;tag=" + legFromTag;

	// ── Draw everything BEFORE mutating or sending (#101A). A transfer touches two
	// dialogs' worth of wire state; refusing halfway would leave the transferor
	// dropped with nobody invited, which is the #197 bug in a different costume.
	std::shared_ptr<SipMessage> inviteToTarget;
	{
		// The transferee's own media, relayed peer-to-peer. Normalised to sendrecv:
		// every phone's Transfer softkey holds the call before it REFERs, so the
		// last SDP captured for the transferee is routinely a hold offer/answer.
		// Relaying that direction verbatim would complete the transfer with one-way
		// audio (see sipwire::sdpAsSendrecv).
		const std::string offer = sipwire::sdpAsSendrecv(transfereeSdp);
		std::ostringstream ss;
		ss << "INVITE sip:" << target << "@"
		   << sipwire::addrToIpPort(targetClient.value()->getAddress()) << " SIP/2.0\r\n"
		   << "Via: SIP/2.0/UDP " << srcIpPort << ";branch=" << legBranch << "\r\n"
		   << "From: " << legFrom << "\r\n"
		   << "To: <sip:" << target << "@" << srcIpPort << ">\r\n"
		   << legCallID << "\r\n"
		   << "CSeq: 1 INVITE\r\n"
		   << "Max-Forwards: 70\r\n"
		   << "Contact: <sip:" << transferee->getNumber() << "@" << srcIpPort << ";transport=UDP>\r\n"
		   // RFC 3892: who caused this INVITE to be sent. Cheap, and it is the only
		   // trace of the transferor left on the leg once they are dropped.
		   << "Referred-By: <sip:" << transferor->getNumber() << "@" << srcIpPort << ">\r\n"
		   << "User-Agent: pocket-dial\r\n"
		   << "Content-Type: application/sdp\r\n"
		   << "Content-Length: " << offer.size() << "\r\n\r\n"
		   << offer;
		inviteToTarget = getMessageFromPool(ss.str(), targetClient.value()->getAddress());
	}

	// The BYE that drops the transferor — the mirror image of the pre-#197 one in
	// every slot. It is addressed to the TRANSFEROR, and the server sends it
	// impersonating the transferee, so From carries the transferee's tag and To the
	// transferor's: the REFER's own To/From, swapped (the REFER travelled A->B, this
	// BYE travels B->A). Getting these backwards produces a message the phone
	// rejects as a stranger's dialog, which is why #128 regression-tests the slots.
	// Issue #402: the NOTIFY and this BYE both go to the transferor on this one
	// dialog, so each needs its own CSeq above everything the dialog has carried.
	// They used to share a hardcoded 2 and the phone 500'd the BYE.
	const uint32_t xferBase = original->nextServerCSeq();   // NOTIFY, then BYE
	auto byeToTransferor = buildServerBye(transferor->getNumber(), transferor->getAddress(),
		callID, std::string(data->getTo()), std::string(data->getFrom()), xferBase + 1);

	// NOTE (issue #197, secondary item 1): this sipfrag still claims 200 OK the
	// moment the INVITE is queued, before the target has been rung. RFC 3515 §2.4.5
	// wants the referred request's ACTUAL final response, preceded by a 100 Trying
	// notification (§2.4.4). Deliberately NOT changed here: it is a separate defect
	// with its own failure mode (a phone told the truth late vs. told a lie early),
	// and folding it in would make this change about two things.
	auto notify = buildReferNotify(data, transferor, "SIP/2.0 200 OK", /*terminated=*/true,
		xferBase);

	auto legSession = allocateSession(legCallID, transferee);

	if (!inviteToTarget || !byeToTransferor || !notify || !legSession)
	{
		// Nothing has been sent but the 202 and nothing has been mutated, so the
		// transferor's REFER retransmit retries the whole transfer from scratch.
		// An unpublished legSession is reclaimed by the next allocateSession()
		// scan. Same answer as #203: refuse without destroying a working call.
		queueLog("REFER: blind transfer to " + target + " not started — pool exhausted", true);
		return;
	}

	// The transferee's offer relayed peer-to-peer: keep its preference order, drop
	// only payloads this PBX will not carry (the same treatment buildInviteFork
	// gives an ordinary fork).
	(void)inviteToTarget->filterAudioCodecs(/*allowWideband=*/true);
	inviteToTarget->syncContentLength();

	// ── The leg toward the target. The server is the UAC on it: it minted the
	// INVITE, so every response belongs to us, not to the transferee whose identity
	// it borrows. isBlindXferLeg() is what routes those responses to
	// handleBlindXferOk()/handleBlindXferFailure() instead of the generic relays,
	// which would forward them into the transferee's dialog, whose Call-ID and tags
	// they do not match.
	legSession->setDest(targetClient.value());
	legSession->setBlindXferLeg(true);
	legSession->setLocalTag(legFromTag);
	legSession->setUacBranch(legBranch);   // a non-2xx ACK must reuse the INVITE's branch
	legSession->setInviteMessage(inviteToTarget);
	legSession->setPeerCallID(callID);
	// Our own side of the leg's dialog now; the target's To-tag is stamped in when
	// it answers (handleBlindXferOk) — it does not exist yet. Stored WITH the header
	// name, the convention every other setDialogHeaders() caller follows (they pass
	// data->getFrom(), which is the whole line) and what the stripHeaderName() in
	// buildServerBye and the ACK builders expects to be handed.
	legSession->setDialogHeaders("From: " + legFrom, std::string());
	_sessions.emplace(legCallID, legSession);

	// ── The A-B dialog SURVIVES, as the transferee's half of the bridge. This is
	// the whole point of #197: endCall() is NOT called here. The transferee stays on
	// its own dialog throughout — same Call-ID, same tags, no reconnect — and only
	// its media is re-pointed once the target answers.
	original->setPeerCallID(legCallID);
	original->setTransferBridge(true);
	original->setWasTransferorSrc(transferorIsSrc);
	// REFER is an in-dialog request on this very dialog, so its From/To are this
	// dialog's authoritative tags. Re-stamp them in src/dest orientation:
	// getDialogFrom/To() is otherwise only populated by onOk() at connect time, and
	// both the BYE relay and the re-INVITE below depend on them being real.
	original->setDialogHeaders(
		transferorIsSrc ? std::string(data->getFrom()) : std::string(data->getTo()),
		transferorIsSrc ? std::string(data->getTo()) : std::string(data->getFrom()));

	_outbox.emplace_back(targetClient.value()->getAddress(), std::move(inviteToTarget));
	// NOTIFY BEFORE the BYE. Both go to the transferor, and the NOTIFY is an
	// in-dialog request on the REFER's own dialog: send the BYE first and the phone
	// has every right to 481 the notification it is waiting for.
	_outbox.emplace_back(transferor->getAddress(), std::move(notify));
	_outbox.emplace_back(transferor->getAddress(), std::move(byeToTransferor));
	original->noteServerCSeq(xferBase + 1);

	queueLog("REFER: blind transfer " + transferee->getNumber() + " -> " + target +
		" (transferor " + transferor->getNumber() + " dropped)");
}

void RequestsHandler::onMessage(std::shared_ptr<SipMessage> data)
{
	// Inbound MESSAGE hygiene (RFC 3428). Phones may send delivery receipts / IMs;
	// if we don't 200 them they retransmit. We do NOT interpret the body and the
	// server never originates a MESSAGE. Simple stateless ack, mirroring onOptions().
	auto response = getMessageFromPool(*data);
	if (!response) return;   // pool exhausted: drop, peer retransmits (#101A)
	response->setHeader(SipMessageTypes::OK);
	response->clearBody();
	response->setVia(sipwire::viaWithReceived(data->getVia(), data->getSource()));
	response->setTo(std::string(data->getTo()) + ";tag=" + IDGen::GenerateID(9));
	_outbox.emplace_back(data->getSource(), std::move(response));
}

std::shared_ptr<SipMessage> RequestsHandler::buildReferNotify(const std::shared_ptr<SipMessage>& refer,
	const std::shared_ptr<SipClient>& transferor,
	const std::string& sipfrag,
	bool terminated,
	uint32_t cseq)
{
	// RFC 3515 §2.4.5 NOTIFY: Event: refer + message/sipfrag body reporting the
	// transfer result. Sent within the REFER's dialog back to the transferor.
	std::string activeIp = _localIp;
	std::string destIpPort = sipwire::addrToIpPort(transferor->getAddress());
	std::string srcIpPort = activeIp + ":" + std::to_string(_serverPort);
	std::string branch = "z9hG4bK" + IDGen::GenerateID(12);

	std::string body = sipfrag + "\r\n";
	std::string subState = terminated ? "terminated;reason=noresource" : "active;expires=60";

	std::ostringstream ss;
	ss << "NOTIFY sip:" << transferor->getNumber() << "@" << destIpPort << " SIP/2.0\r\n"
	   << "Via: SIP/2.0/UDP " << srcIpPort << ";branch=" << branch << "\r\n"
	   // getTo()/getFrom()/getCallID() hand back the FULL header line, so the value
	   // has to be unwrapped before it is re-stamped under a new name — otherwise
	   // this NOTIFY goes out as "From: To: <sip:...>" and the transferor cannot
	   // match it to the REFER dialog. Roles swap (RFC 3515 §2.4.5).
	   << "From: " << stripHeaderName(refer->getTo()) << "\r\n"
	   << "To: " << stripHeaderName(refer->getFrom()) << "\r\n"
	   << "Call-ID: " << stripHeaderName(refer->getCallID()) << "\r\n"
	   << "CSeq: " << cseq << " NOTIFY\r\n"
	   << "Max-Forwards: 70\r\n"
	   << "Event: refer\r\n"
	   << "Subscription-State: " << subState << "\r\n"
	   << "Contact: <sip:" << pbx::kServiceServer << "@" << srcIpPort << ">\r\n"
	   << "User-Agent: pocket-dial\r\n"
	   << "Content-Type: message/sipfrag;version=2.0\r\n"
	   << "Content-Length: " << body.size() << "\r\n\r\n"
	   << body;

	return getMessageFromPool(ss.str(), transferor->getAddress());
}

bool RequestsHandler::handleTransferOk(const std::shared_ptr<SipMessage>& data)
{
	// Recognised by Call-ID membership in _transferPendingAcks, not by CSeq value
	// — same recognise-by-Call-ID-in-a-tracking-vector pattern as ParkOrbit::
	// handleOk's pendingAcks scan. The three splice/swap re-INVITEs that populate
	// that vector no longer share one hardcoded CSeq (issue #257 gave the blind-
	// transfer one a real, dialog-specific value), so this ACK's own CSeq is
	// pulled from the response itself: RFC 3261 s8.2.6.2 requires a 200 OK to
	// echo the SAME CSeq number as the request it answers, and s17.1.1.3 requires
	// the ACK to carry that identical number. Deriving it here means this
	// function is correct for whatever CSeq any of the three re-INVITEs used,
	// present or future, rather than assuming they all agree on one constant.
	if (data->getCSeq().find(SipMessageTypes::INVITE) == std::string::npos) return false;
	const std::string callID(data->getCallID());
	auto it = std::find(_transferPendingAcks.begin(), _transferPendingAcks.end(), callID);
	if (it == _transferPendingAcks.end()) return false;
	const uint32_t ackCseq = siphdr::cseqNumber(data->getCSeq());

	std::string activeIp = _localIp;
	std::string srcIpPort = activeIp + ":" + std::to_string(_serverPort);
	std::string destIpPort = sipwire::addrToIpPort(data->getSource());

	std::ostringstream ss;
	ss << "ACK sip:" << data->getToNumber() << "@" << destIpPort << " SIP/2.0\r\n"
	   << "Via: SIP/2.0/UDP " << srcIpPort << ";branch=z9hG4bK" << IDGen::GenerateID(12) << "\r\n"
	   << "From: " << stripHeaderName(data->getFrom()) << "\r\n"
	   << "To: " << stripHeaderName(data->getTo()) << "\r\n"
	   << "Call-ID: " << stripHeaderName(callID) << "\r\n"
	   << "CSeq: " << ackCseq << " ACK\r\n"
	   << "Max-Forwards: 70\r\n"
	   << "Content-Length: 0\r\n\r\n";
	auto ack = getMessageFromPool(ss.str(), data->getSource());
	if (!ack) return true;   // pool exhausted: drop, peer retransmits the 200 OK (#101A) —
	                          // entry stays so the retransmit still lands here, not the
	                          // generic relay below (which would forward it toward A).
	_outbox.emplace_back(data->getSource(), std::move(ack));
	_transferPendingAcks.erase(it);

	// This 200 OK answers a re-INVITE that re-pointed a phone's media at its new
	// peer, so whatever hold that dialog was in has just ended. A transferor's
	// Transfer softkey holds the call before it REFERs (and a consult does the
	// same), so the session is routinely still Held here — leaving it that way
	// would have the dashboard, the session-timer sweep and any later resume all
	// reasoning about a call that is in fact talking.
	if (auto spliced = getSession(callID);
		spliced.has_value() && spliced.value()->getState() == Session::State::Held)
	{
		spliced.value()->setState(Session::State::Connected);
	}
	return true;
}

bool RequestsHandler::handleBlindXferOk(const std::shared_ptr<SipMessage>& data)
{
	// The blind-transfer TARGET answered (issue #197). The server is the UAC on
	// this leg — it minted the INVITE, borrowing the transferee's identity — so
	// this 200 OK is addressed to US and must never reach the generic relay in
	// onOk(), which would forward it to the session's src (the transferee) inside
	// a dialog the transferee has never seen.
	//
	// Two things happen here, and only here: the leg gets its ACK, and the media
	// swap that makes the transfer real gets completed — the transferee is
	// re-INVITEd, inside its OWN untouched dialog, with the target's SDP. That is
	// ParkOrbit's retrieve swap, arriving one round-trip late because the target
	// had to be rung before it had an answer to swap in.
	if (data->getCSeq().find(SipMessageTypes::INVITE) == std::string::npos) return false;
	const std::string callID(data->getCallID());
	auto legOpt = getSession(callID);
	if (!legOpt.has_value() || !legOpt.value()->isBlindXferLeg()) return false;
	auto leg = legOpt.value();

	const std::string srcIpPort = _localIp + ":" + std::to_string(_serverPort);

	// ACK on EVERY arrival, not just the first. A 2xx is retransmitted until its
	// UAC ACKs it, and this intercept is keyed off a session flag rather than a
	// one-shot tracking entry precisely so a retransmit still lands here and still
	// gets acknowledged, instead of falling through to the relay once an entry had
	// been consumed.
	{
		std::ostringstream ss;
		ss << "ACK sip:" << data->getToNumber() << "@"
		   << sipwire::addrToIpPort(data->getSource()) << " SIP/2.0\r\n"
		   << "Via: SIP/2.0/UDP " << srcIpPort << ";branch=z9hG4bK" << IDGen::GenerateID(12) << "\r\n"
		   << "From: " << stripHeaderName(data->getFrom()) << "\r\n"
		   << "To: " << stripHeaderName(data->getTo()) << "\r\n"
		   << "Call-ID: " << stripHeaderName(callID) << "\r\n"
		   << "CSeq: 1 ACK\r\n"
		   << "Max-Forwards: 70\r\n"
		   << "Content-Length: 0\r\n\r\n";
		auto ack = getMessageFromPool(ss.str(), data->getSource());
		if (!ack) return true;   // pool exhausted: the target retransmits its 200 OK (#101A)
		_outbox.emplace_back(data->getSource(), std::move(ack));
	}

	// Already swapped: this is a retransmit. It got its ACK above; re-INVITEing the
	// transferee a second time would restart an offer/answer it has already
	// completed.
	if (leg->getState() == Session::State::Connected) return true;

	auto origOpt = getSession(leg->getPeerCallID());
	std::shared_ptr<Session> orig = origOpt.has_value() ? origOpt.value() : nullptr;
	auto transferee = orig ? (orig->wasTransferorSrc() ? orig->getDest() : orig->getSrc()) : nullptr;
	if (!orig || !transferee || orig->getDialogFrom().empty() || orig->getDialogTo().empty())
	{
		// The transferee hung up between our INVITE and this answer. There is
		// nothing left to bridge the target to, and it is now talking to a call
		// that no longer exists — end it rather than leave it there (the #128 rule:
		// never leave a party on a call the server considers over).
		if (auto tgt = leg->getDest())
		{
			auto bye = buildServerBye(tgt->getNumber(), tgt->getAddress(), callID,
				leg->getDialogFrom(), std::string(data->getTo()));
			if (bye) _outbox.emplace_back(tgt->getAddress(), std::move(bye));
		}
		endCall(callID, leg->getSrc() ? leg->getSrc()->getNumber() : std::string(),
			leg->getDest() ? leg->getDest()->getNumber() : std::string(),
			"blind transfer: transferee gone before the target answered");
		queueLog("REFER: blind transfer target answered but the transferee had gone — "
			"target released", true);
		return true;
	}

	// The re-INVITE impersonates the departed transferor inside the transferee's
	// dialog: those are the tags that phone's dialog expects, and they are the only
	// ones it will accept. Which of the pair is the transferor flips with
	// orientation (the receptionist case has them as the callee), which is what
	// wasTransferorSrc() recorded at transfer time.
	const std::string& transferorHdr = orig->wasTransferorSrc() ? orig->getDialogFrom()
		: orig->getDialogTo();
	const std::string& transfereeHdr = orig->wasTransferorSrc() ? orig->getDialogTo()
		: orig->getDialogFrom();

	// Issue #257, then #402. This impersonates A inside A-B's PRE-EXISTING dialog,
	// so its CSeq must exceed everything B has seen there -- A's REFER (#257's
	// floor) and, since #402, whatever the server itself already sent on this
	// dialog in A's or B's name (the NOTIFY and BYE of onRefer). nextServerCSeq()
	// covers both; the REFER floor stays as a belt-and-braces lower bound.
	// handleTransferOk() ACKs with whatever CSeq the 200 echoes, so nothing
	// downstream needs this number -- only that it is real and monotonic.
	const uint32_t swapCSeq = std::max(orig->transferorCseqAtRefer() + 1, orig->nextServerCSeq());

	std::shared_ptr<SipMessage> reinvite;
	{
		// The target's answer becomes the transferee's new offer. Normalised to
		// sendrecv for the same reason the outbound offer was: the transferee may
		// still be on hold from the moment the transferor pressed Transfer, and a
		// re-INVITE that re-points its media is exactly where that hold ends.
		const std::string offer = sipwire::sdpAsSendrecv(std::string(data->getBody()));
		std::ostringstream ss;
		ss << "INVITE sip:" << transferee->getNumber() << "@"
		   << sipwire::addrToIpPort(transferee->getAddress()) << " SIP/2.0\r\n"
		   << "Via: SIP/2.0/UDP " << srcIpPort << ";branch=z9hG4bK" << IDGen::GenerateID(12) << "\r\n"
		   << "From: " << stripHeaderName(transferorHdr) << "\r\n"
		   << "To: " << stripHeaderName(transfereeHdr) << "\r\n"
		   << "Call-ID: " << stripHeaderName(leg->getPeerCallID()) << "\r\n"
		   << "CSeq: " << swapCSeq << " INVITE\r\n"
		   << "Max-Forwards: 70\r\n"
		   << "Contact: <sip:" << transferee->getNumber() << "@" << srcIpPort << ">\r\n"
		   << "User-Agent: pocket-dial\r\n"
		   << "Content-Type: application/sdp\r\n"
		   << "Content-Length: " << offer.size() << "\r\n\r\n"
		   << offer;
		reinvite = getMessageFromPool(ss.str(), transferee->getAddress());
	}
	if (!reinvite)
	{
		// Drawn before any state change on purpose: the leg is still not Connected,
		// so the target's 200 OK retransmit comes straight back here and the swap is
		// retried. Claiming the bridge now would strand the transferee on the old
		// media path with no second chance (#101A).
		return true;
	}
	(void)reinvite->filterAudioCodecs(/*allowWideband=*/true);   // phone SDP relayed P2P
	reinvite->syncContentLength();

	leg->setState(Session::State::Connected);
	leg->setDialogHeaders(leg->getDialogFrom(), std::string(data->getTo()));   // target's To-tag
	leg->setRemoteSdp(std::string(data->getBody()));
	leg->setTransferBridge(true);
	// On this leg the absent party the server impersonates — onBye's bridge relay
	// calls it "A" — is the transferee, which is this session's src. So the
	// surviving party that relay must address is getDest(), the target. Same field,
	// same meaning as the attended splice gives it: "the impersonated side is src".
	leg->setWasTransferorSrc(true);
	_transferPendingAcks.push_back(leg->getPeerCallID());
	_outbox.emplace_back(transferee->getAddress(), std::move(reinvite));
	orig->noteServerCSeq(swapCSeq);

	queueLog("REFER: blind transfer completed — " + transferee->getNumber() + " <-> " +
		(leg->getDest() ? leg->getDest()->getNumber() : std::string("?")));
	return true;
}

bool RequestsHandler::handleBlindXferFailure(const std::shared_ptr<SipMessage>& data)
{
	// A non-2xx final to the INVITE we sent the blind-transfer target: busy,
	// declined, gone, whatever. Same intercept-before-everything shape as
	// _beeper.handleInviteFailure(), and for the same two reasons — the response is
	// ours to ACK (nobody else will), and left alone it would be interpreted as a
	// failure of a call the transferee placed. onBusy()'s CFB lookup used to read
	// data->getFromNumber() here, the TRANSFEREE's number on this leg, not the
	// busy party; fixed to data->getToNumber() by #256. This intercept still
	// stands regardless, for the ACK-ownership reason above. (Noted in review:
	// getToNumber() now resolves to the transfer TARGET on this leg, the real
	// busy party, so if this intercept were ever removed, onBusy() would apply
	// the TARGET's own CFB config to a failed blind transfer, not misroute on
	// the transferee's identity like before -- a different, still-questionable
	// interaction, not the #256 bug. Out of scope here; flagging for whoever
	// next touches this intercept.)
	if (data->getCSeq().find(SipMessageTypes::INVITE) == std::string::npos) return false;
	const std::string callID(data->getCallID());
	auto legOpt = getSession(callID);
	if (!legOpt.has_value() || !legOpt.value()->isBlindXferLeg()) return false;
	auto leg = legOpt.value();

	const std::string srcIpPort = _localIp + ":" + std::to_string(_serverPort);

	// RFC 3261 §17.1.1.3: a non-2xx final is ACKed inside the INVITE's own
	// transaction — same Call-ID, same From-tag, and the SAME Via branch as the
	// INVITE, which is what setUacBranch() captured at transfer time. Without this
	// the target retransmits its 486 until Timer H fires.
	{
		std::ostringstream ss;
		ss << "ACK sip:" << data->getToNumber() << "@"
		   << sipwire::addrToIpPort(data->getSource()) << " SIP/2.0\r\n"
		   << "Via: SIP/2.0/UDP " << srcIpPort << ";branch=" << leg->getUacBranch() << "\r\n"
		   << "From: " << stripHeaderName(leg->getDialogFrom()) << "\r\n"
		   << "To: " << stripHeaderName(data->getTo()) << "\r\n"
		   << "Call-ID: " << stripHeaderName(callID) << "\r\n"
		   << "CSeq: 1 ACK\r\n"
		   << "Max-Forwards: 70\r\n"
		   << "Content-Length: 0\r\n\r\n";
		if (auto ack = getMessageFromPool(ss.str(), data->getSource()))
		{
			_outbox.emplace_back(data->getSource(), std::move(ack));
		}
		// A pool refusal only costs retransmits of a response we are about to stop
		// caring about; the teardown below must happen either way, or the transferee
		// is the one left waiting.
	}

	// The transferor has already been dropped and the target has refused, so the
	// transferee is holding a dialog with nobody on the far end and no way back.
	// End it explicitly — the #128 rule again: local bookkeeping alone leaves that
	// phone on a call the server considers over. A nicer PBX would ring the
	// transferor back instead (RFC 5359 §2.4 leaves that to policy); that needs the
	// transferor's leg kept alive through the target's answer, which is a different
	// change.
	if (auto origOpt = getSession(leg->getPeerCallID()); origOpt.has_value())
	{
		auto orig = origOpt.value();
		auto transferee = orig->wasTransferorSrc() ? orig->getDest() : orig->getSrc();
		if (transferee && !orig->getDialogFrom().empty() && !orig->getDialogTo().empty())
		{
			const std::string& transferorHdr = orig->wasTransferorSrc() ? orig->getDialogFrom()
				: orig->getDialogTo();
			const std::string& transfereeHdr = orig->wasTransferorSrc() ? orig->getDialogTo()
				: orig->getDialogFrom();
			auto bye = buildServerBye(transferee->getNumber(), transferee->getAddress(),
				leg->getPeerCallID(), transferorHdr, transfereeHdr);
			if (bye) _outbox.emplace_back(transferee->getAddress(), std::move(bye));
		}
		endCall(leg->getPeerCallID(),
			orig->getSrc() ? orig->getSrc()->getNumber() : std::string(),
			orig->getDest() ? orig->getDest()->getNumber() : std::string(),
			"blind transfer target refused");
	}
	endCall(callID, leg->getSrc() ? leg->getSrc()->getNumber() : std::string(),
		leg->getDest() ? leg->getDest()->getNumber() : std::string(),
		"blind transfer target refused");

	queueLog("REFER: blind transfer target " +
		(leg->getDest() ? leg->getDest()->getNumber() : std::string("?")) +
		" refused the call (" + std::string(data->getHeader()) + ") — transferee released", true);
	return true;
}

bool RequestsHandler::setCallState(std::string_view callID, Session::State state)
{
	auto session = getSession(callID);
	if (session)
	{
		session->get()->setState(state);
		return true;
	}
	return false;
}

void RequestsHandler::endCall(std::string_view callID, std::string_view srcNumber, std::string_view destNumber, std::string_view reason)
{
	// DTMF accumulators are keyed by Call-ID and share the dialog lifecycle; drop
	// this dialog's entry so DtmfFeatureCodes's _dtmfState can't grow unbounded
	// across calls (Fix #4).
	_dtmf.forgetCall(callID);

	// RFC 3261 §17: free any transaction slots tracking retransmits for this call.
	_txLayer.freeForCallId(callID);
	// Free any park orbit slot holding this call's parked leg.
	_park.freeForCallId(callID);
	// Issue #131: a leg that dies mid-splice (before its 200 OK arrives) must not
	// leak its entry in _transferPendingAcks forever -- same bounded-state
	// reasoning as the park orbit line above.
	_transferPendingAcks.erase(
		std::remove(_transferPendingAcks.begin(), _transferPendingAcks.end(), std::string(callID)),
		_transferPendingAcks.end());
	// Drop this call's conference leg, if it had one. Idempotent for every other
	// call, so this is the ONE place a 888 leg is released — BYE, CANCEL, a session
	// timer expiring and the orphan sweep all funnel through endCall(), and none of
	// them has to remember the room exists. Releasing the leg only marks its MixBus
	// port Draining; the next mix tick reclaims the rings without touching the others.
	if (_conference)
	{
		_conference->leave(std::string(callID));
	}

	// Capture the session (for CDR start time / final state) BEFORE we erase it.
	std::shared_ptr<Session> ending;
	auto sit = _sessions.find(std::string(callID));
	if (sit != _sessions.end())
	{
		ending = sit->second;
	}

	// Issue #379 Case B: snapshot the anchor fields HERE, before anything below
	// can reset them. `ending` aliases the pooled Session -- if this dialog's
	// entry in _sessionPool matches callID, the loop further down calls
	// release() on that SAME object (allocateSession() hands out pool slots
	// directly, not copies), and release() unconditionally clears _isAnchor
	// and _anchorParticipantId as part of recycling the slot. A live read of
	// ending->isAnchor()/getAnchorParticipantId() from the anchor-drop block
	// below would see the object AFTER that reset and always find it cleared
	// -- caught by adding this exact fix and finding the new host test still
	// failed once with the object's *current* state instead of its state at
	// the moment this dialog actually ended.
	const bool endingWasAnchor = ending && ending->isAnchor();
	const std::string endingAnchorParticipantId = ending ? ending->getAnchorParticipantId() : std::string();
	const bool endingAnchorLegReleased = ending && ending->isAnchorLegReleased();

	if (_sessions.erase(std::string(callID)) > 0)
	{
		// Record exactly once per torn-down dialog (Phase 2 CDR).
		const CallDetailRecord& rec = _cdr.record(ending, srcNumber, destNumber);

		// Issue #194 Stage 1: queue the same teardown for the SD archive, reusing
		// the CallDetailRecord CdrRing just derived (startMs/durationSec/result)
		// plus the two pieces of context only this call site has and previously
		// discarded -- callID and `reason`. Non-blocking; see CdrArchive.hpp for
		// why this is safe to call here, under _mutex, on the SIP thread.
		cdrarchive::record(rec, callID, reason);

		std::ostringstream message;
		message << "Session has been disconnected between " << srcNumber << " and " << destNumber;
		if (!reason.empty())
		{
			message << " because " << reason;
		}
		queueLog(message.str());
	}

	for (auto& session : _sessionPool)
	{
		if (session->getCallID() == callID)
		{
			session->release();
			break;
		}
	}

	// Media beachhead safety net: if the dialog being torn down owns the live RTP
	// tone stream (BYE/CANCEL paths already call stop(); this also covers lease
	// expiry / force-disconnect / hunt cleanup that route through endCall()), stop
	// it so the socket + 20 ms task never leak past the call. Idempotent no-op when
	// the stream is idle or owned by a different Call-ID.
	_rtpSender.stop(std::string(callID));

	// Anchor-bridge safety net (same shape as the RTP tone-stream stop above): if
	// the dialog being torn down owns a live anchor MediaBridge, best-effort drop
	// the anchor-side leg and release the bridge so its RTP sockets/pacing task
	// never outlive the call. Idempotent no-op when no bridge is bridging this
	// Call-ID (the ordinary case for every non-555 call). Every OUTBOUND-anchor
	// teardown path (onCancel/onBye's kAnchorCallExt branches, tick()'s no-answer/
	// ACK-deadline reap) funnels through here rather than dropping the leg
	// itself, so this is the ONE place that must pick sync vs async — see
	// anchorIsSynchronous()'s doc comment for why calling dropCall() directly
	// would stall the SIP thread for a real anchor's TLS round trip.
	{
		const std::string callIdStr(callID);
		bool droppedViaBridge = false;
		for (auto& bridge : _mediaBridges)
		{
			if (bridge.isForCallId(callIdStr))
			{
				const std::string participantId = bridge.participantId();
				if (_anchorClient && !participantId.empty())
				{
					if (anchorIsSynchronous())
					{
						_anchorClient->dropCall(participantId);
					}
					else
					{
						asyncDropCall(participantId);
					}
					droppedViaBridge = true;
				}
				bridge.stopBridge();
				break;
			}
		}

		// Issue #379 Case B: a MediaBridge is created only once media actually
		// bridges (after the leg is Answered). A CANCEL/teardown that arrives
		// while the call is still ringing finds NO bridge here -- the loop
		// above drops nothing, and the leg asyncMakeCall() already placed on
		// 3CX is orphaned: live, ringable, answerable, and billed, with no one
		// left to drop it. Reproduced live: hang up during setup and the far
		// end still rang, was answered, and stayed up ~40 s with nobody local.
		//
		// Gated on droppedViaBridge (did we actually issue a drop), not on
		// whether a bridge slot matched: MediaBridge::startBridge() sets
		// _callID and _participantId together, before _active, all under the
		// same mutex isForCallId()/participantId() take -- so a matched slot
		// with an empty participantId() is not reachable today. Naming the
		// gate this way means that stays true by construction rather than by
		// a reader re-deriving MediaBridge's locking discipline.
		//
		// The session already carries the leg id independently --
		// setAnchorParticipantId() is set the moment makeCall() returns (see
		// asyncMakeCall()/bindOutboundParticipant()), well before any bridge
		// exists -- and the WS event classifier already trusts that copy
		// (search getAnchorParticipantId() above). Teardown didn't. Fall back
		// to it here, same sync/async split as the bridge-found case above.
		//
		// Reads the SNAPSHOT taken before this function's _sessionPool loop
		// (above) could have already called release() on this same object and
		// cleared both fields -- see that snapshot's own comment.
		//
		// Skipped when the caller already released the leg. Most anchor
		// teardowns (the CallEvent::Dropped handler, the no-answer reaps,
		// inbound busy/unavailable/bridge-failed, the degraded-audio sweep)
		// stop the bridge and drop the leg -- or learn 3CX already did --
		// BEFORE calling endCall(); the stopped bridge makes droppedViaBridge
		// false above, so without this gate every one of them dropped the same
		// leg twice. A path that drops the leg itself must also call
		// setAnchorLegReleased(); one that forgets double-drops, and logs it
		// with the line below, rather than orphaning a billable leg in silence.
		if (!droppedViaBridge && !endingAnchorLegReleased && _anchorClient && endingWasAnchor)
		{
			const std::string& fallbackParticipantId = endingAnchorParticipantId;
			if (!fallbackParticipantId.empty())
			{
				queueLog("[Telephony] Anchor leg " + fallbackParticipantId +
					" torn down before it bridged -- dropping orphaned leg (#379)", true);
				if (anchorIsSynchronous())
				{
					_anchorClient->dropCall(fallbackParticipantId);
				}
				else
				{
					asyncDropCall(fallbackParticipantId);
				}
			}
		}
	}

	// Voicemail-leg safety net (Issue #246, same shape as the anchor-bridge one
	// above): a leg claimed by answerVoicemailDeposit() must be released on
	// EVERY teardown path, not just onBye() -- session-timer expiry,
	// forceDisconnect()/admin hangup and the orphan sweep all funnel through
	// endCall() too, and none of them should have to remember this pool
	// exists. Found in review: releasing only from onBye() left the RTP
	// receiver/sender running and the slot claimed forever on any other path.
	// Keyed on the session flag (ending->isVoicemail()), not destNumber or the
	// dest's name -- same reasoning as isAnchor()'s own doc comment.
	if (ending && ending->isVoicemail())
	{
		const int vmSlot = ending->getVoicemailLegSlot();
		enqueueVoicemailFlush(vmSlot);
		releaseVoicemailLeg(vmSlot, std::string(callID));
	}

	// Issue #164, same discipline as the voicemail release directly above and
	// for the same reason: every teardown path funnels through endCall(), so
	// releasing here covers BYE, CANCEL, forceDisconnect and the sweeps at
	// once. Keyed on the session flag, never on the destination -- by now the
	// dialled number is a PSTN string that looks like nothing in particular.
	//
	// hangup() is idempotent on an unknown Call-ID, which matters because the
	// carrier-initiated paths reach endCall() with the trunk dialog already
	// released: onTrunkFailed and onTrunkRemoteBye both free it before calling
	// in. Only the handset-initiated paths actually need the BYE sent here.
	if (ending && ending->isTrunk())
	{
		_sipTrunk.hangup(callID);
		releaseTrunkRelay(ending->getTrunkRelaySlot());
	}
}

uint64_t RequestsHandler::nowEpochMs() const
{
	return static_cast<uint64_t>(
		std::chrono::duration_cast<std::chrono::milliseconds>(
			std::chrono::steady_clock::now().time_since_epoch()).count());
}

void RequestsHandler::unregisterClient(std::string_view number)
{
	queueLog("Unregistered client: " + std::string(number));
	for (auto& client : _clientPool)
	{
		if (client->getNumber() == number)
		{
			client->release();
			break;
		}
	}
}

int RequestsHandler::parseRequestedExpires(const std::shared_ptr<SipMessage>& data) const
{
	// Helper: read a non-negative integer starting at `from`. Returns -1 if no digits.
	auto readInt = [](const std::string& s, size_t from) -> int {
		while (from < s.size() && std::isspace(static_cast<unsigned char>(s[from]))) ++from;
		size_t end = from;
		while (end < s.size() && std::isdigit(static_cast<unsigned char>(s[end]))) ++end;
		if (end == from) return -1;
		int val = 0;
		for (size_t i = from; i < end; ++i)
		{
			if (val > 200000000) return 200000000;
			val = val * 10 + (s[i] - '0');
		}
		return val;
	};

	// 1. expires= parameter on the Contact header (most common form).
	std::string contact(data->getContact());
	auto cpos = contact.find("expires=");
	if (cpos != std::string::npos)
	{
		int v = readInt(contact, cpos + 8);
		if (v >= 0) return v;
	}

	// 2. Standalone Expires header — scan only lines beginning with 'e'/'E' to
	//    avoid copying and lowercasing the entire message (which includes the SDP body).
	const std::string& raw = data->toString();
	size_t pos = 0;
	while (pos < raw.size())
	{
		size_t lineEnd = raw.find('\n', pos);
		size_t next = (lineEnd == std::string::npos) ? raw.size() : lineEnd + 1;
		char first = raw[pos];
		if (first == 'e' || first == 'E')
		{
			// Check for "expires:" (case-insensitive, 8 chars + colon)
			if (next - pos >= 9)
			{
				std::string name = raw.substr(pos, 8);
				std::transform(name.begin(), name.end(), name.begin(),
					[](unsigned char c){ return static_cast<char>(std::tolower(c)); });
				if (name == "expires:")
				{
					// Skip past any \r before \n in the offset calculation
					int v = readInt(raw, pos + 8);
					if (v >= 0) return v;
				}
			}
		}
		else if (first == '\r' || first == '\n')
		{
			break; // reached the header/body boundary blank line
		}
		pos = next;
	}

	// 3. No expiry specified — grant the default lease.
	return DEFAULT_EXPIRES;
}

void RequestsHandler::sweepExpired()
{
	auto now = std::chrono::steady_clock::now();
	for (auto& client : _clientPool)
	{
		if (client->getNumber().empty())
			continue;

		bool keepAliveTimedOut = (now - client->getLastActiveTime() > std::chrono::seconds(15));
		bool leaseExpired = client->isExpired(now);

		if (keepAliveTimedOut || leaseExpired)
		{
			if (keepAliveTimedOut)
			{
				queueLog("Pruning client due to missed OPTIONS keepalive pings: " + client->getNumber());
			}
			else
			{
				queueLog("Registration lease expired: " + client->getNumber());
			}

			// Clean up sessions involving this client
			std::string extension = client->getNumber();
			for (auto sit = _sessions.begin(); sit != _sessions.end(); )
			{
				bool involved = false;
				if (sit->second->getSrc() && sit->second->getSrc()->getNumber() == extension)
					involved = true;
				if (sit->second->getDest() && sit->second->getDest()->getNumber() == extension)
					involved = true;
				if (involved)
				{
					std::string callID = sit->first;
					// Media beachhead: if this dialog owned the live RTP tone stream,
					// stop it so a caller whose lease expires mid-stream doesn't leak
					// the socket/task. Idempotent no-op otherwise.
					_rtpSender.stop(callID);
					sit = _sessions.erase(sit);
					for (auto& session : _sessionPool)
					{
						if (session->getCallID() == callID)
						{
							session->release();
							break;
						}
					}
				}
				else
				{
					++sit;
				}
			}

			client->release();
		}
	}
}

void RequestsHandler::maybeSweep()
{
	auto now = std::chrono::steady_clock::now();
	if (now - _lastSweep < SWEEP_INTERVAL)
	{
		return;
	}
	_lastSweep = now;
	sweepExpired();
}

std::optional<std::shared_ptr<SipClient>> RequestsHandler::findClient(std::string_view number)
{
	for (auto& client : _clientPool)
	{
		if (client->getNumber() == number)
			return client;
	}
	return {};
}

std::shared_ptr<SipClient> RequestsHandler::findServicePeer(std::string_view number)
{
	// Issue #202. The fallback half of findRegistered(): scanned only AFTER
	// _clientPool misses, and kept out of findClient() itself so that "is a phone
	// registered under this number" keeps its old, narrower answer everywhere it
	// is asked (onInvite's callee lookup, onRegister's new-binding test, endHandle,
	// forceDisconnect, and the register-beep paths that depend on findClient("pbx")
	// MISSING).
	//
	// The dialable gate is the point, not a formality: a service marked false is
	// still a RESERVED name the engine owns, but it is not a place a call may be
	// sent. Every seeded service is false today — see ServiceExtensions.hpp for
	// why (the loopback INVITE is dropped by onInvite's own retransmission guard
	// until the engine can mint a fresh Call-ID for the inner leg), and note that
	// answering a routing caller with a peer we cannot actually deliver to would
	// be worse than the miss it replaces: redirectInvite() would report success
	// and the CFU fall-through to the original callee would be skipped.
	const int idx = pbx::serviceEndpointIndex(number);
	if (idx < 0) return nullptr;
	if (!pbx::kServiceEndpoints[static_cast<std::size_t>(idx)].dialable) return nullptr;
	return _servicePeers[static_cast<std::size_t>(idx)];
}

void RequestsHandler::endHandle(std::string_view destNumber, std::shared_ptr<SipMessage> message)
{
	auto destClient = findClient(destNumber);
	if (destClient.has_value())
	{
		_outbox.emplace_back(destClient.value()->getAddress(), std::move(message));
	}
	else
	{
		// Clone the message so we don't mutate a shared object's header
		auto notFound = getMessageFromPool(*message);
		if (!notFound) return;   // pool exhausted: drop, peer retransmits (#101A)
		notFound->setHeader(SipMessageTypes::NOT_FOUND);
		notFound->clearBody();
		auto src = message->getSource();
		_outbox.emplace_back(src, std::move(notFound));
	}
}

std::string RequestsHandler::buildContact(std::string_view number) const
{
	std::string activeIp = _localIp;
	return "Contact: <sip:" + std::string(number) + "@" + activeIp + ":" + std::to_string(_serverPort) + ";transport=UDP>";
}

// ── Dashboard query API ──────────────────────────────────────────────────────

static const char* sessionStateToString(Session::State s)
{
	switch (s)
	{
		case Session::State::Invited:     return "Invited";
		case Session::State::Connected:   return "Connected";
		case Session::State::Busy:        return "Busy";
		case Session::State::Unavailable: return "Unavailable";
		case Session::State::Cancel:      return "Cancel";
		case Session::State::Bye:         return "Bye";
		default:                          return "Unknown";
	}
}

std::vector<std::pair<std::string, std::string>> RequestsHandler::getActiveClients()
{
	std::lock_guard<std::mutex> lock(_snapshotMutex);
	return _snapshot.clients;
}

std::vector<std::tuple<std::string, std::string, std::string, int>> RequestsHandler::getActiveSessions()
{
	std::lock_guard<std::mutex> lock(_snapshotMutex);
	return _snapshot.sessions;
}

void RequestsHandler::forceDisconnect(const std::string& extension)
{
	std::vector<std::pair<bool, std::string>> localLogs;
	{
		std::lock_guard<std::mutex> lock(_mutex);
		queueLog("Admin: force-disconnecting extension " + extension);
		// Issue #228: tear down every dialog this extension is on the way every
		// other server-initiated teardown does — BYE the phones, THEN endCall().
		//
		// Until this landed the loop below erased the Session and released its
		// pool slot inline and sent nothing, so the far-end phone (and the killed
		// extension's own handset) kept a call the PBX had already forgotten: P2P
		// media carried on, and the phones only found out when one of them hung
		// up locally into a 481. The inline erase also skipped everything
		// endCall() owns besides the session map — the DTMF accumulator, the
		// transaction-layer slots for the Call-ID, the park orbit, the conference
		// leg and the CDR record — so a killed call never produced a CDR entry.
		//
		// Shape mirrors sweepSessionTimers(): one server BYE per leg, addressed
		// with the dialog From/To captured at connect, then endCall() for the
		// rest. Both legs get one — the admin killed the CALL, and the killed
		// extension's handset has just as little way to learn that as its peer.
		//
		// Thread rule: /api/kill reaches here from the HTTP task, not the SIP
		// receive thread, so the BYEs go to _asyncOutbox. handle()/tick() clear
		// _outbox at the start of every pass; a push there from this thread
		// would race that clear and be silently dropped. drainOutbox() merges
		// _asyncOutbox on the SIP thread's next pass.
		//
		// Collect first, then act: endCall() erases from _sessions, so it cannot
		// run inside an iteration over that map.
		std::vector<std::string> involved;
		for (const auto& [callID, session] : _sessions)
		{
			if ((session->getSrc()  && session->getSrc()->getNumber()  == extension) ||
				(session->getDest() && session->getDest()->getNumber() == extension))
			{
				involved.push_back(callID);
			}
		}
		for (const auto& callID : involved)
		{
			auto it = _sessions.find(callID);
			if (it == _sessions.end()) continue;
			auto session = it->second;
			auto src  = session->getSrc();
			auto dest = session->getDest();
			const std::string& dFrom = session->getDialogFrom();
			const std::string& dTo   = session->getDialogTo();

			// Same #72 guard as the session-timer reaper: a BYE with an empty
			// From or To is malformed and phones drop it. A dialog that never
			// reached Connected (still ringing) has no To-tag yet and gets no
			// BYE — endCall() below still clears it server-side, as before.
			if (src && !dFrom.empty() && !dTo.empty())
			{
				auto b = buildServerBye(src->getNumber(), src->getAddress(), callID, dTo, dFrom);
				if (b) _asyncOutbox.emplace_back(src->getAddress(), std::move(b));
			}
			// A virtual-extension leg (777 echo, 888 conference, 555 anchor) has no
			// second phone: its "dest" is a stand-in SipClient carrying the
			// CALLER's own address (see onReinvite()'s note), so a BYE to it would
			// reach the caller a second time with the tags reversed. The PBX is
			// the UAS on that leg, and the src BYE above already ends it.
			const std::string destNum = dest ? dest->getNumber() : "";
			const bool destIsVirtual = destNum == "777" || destNum == ConferenceRoom::EXT ||
			                           destNum == kAnchorCallExt;
			if (dest && !destIsVirtual && !dFrom.empty() && !dTo.empty())
			{
				auto b = buildServerBye(dest->getNumber(), dest->getAddress(), callID, dFrom, dTo);
				if (b) _asyncOutbox.emplace_back(dest->getAddress(), std::move(b));
			}
			endCall(callID,
			        src  ? src->getNumber()  : "",
			        dest ? dest->getNumber() : "",
			        "extension " + extension + " was force-disconnected by admin");
		}
		// Release the registration LAST. SipClient::release() clears the number,
		// and the Session's src/dest point at this same pool object — releasing
		// first (as this function used to) blanked the number before the
		// involvement check above ever ran, so no session matched and nothing
		// was torn down at all. The BYE Request-URIs and the CDR src/dest read
		// the number too.
		for (auto& client : _clientPool)
		{
			if (client->getNumber() == extension)
			{
				client->release();
				break;
			}
		}
		localLogs = std::move(_logQueue);
		_logQueue.clear();
	}

	for (const auto& log : localLogs)
	{
		if (log.first) std::cerr << log.second << '\n';
		else std::cout << log.second << '\n';
	}
}

uint64_t RequestsHandler::getPacketsProcessed() const
{
	return _packetsProcessed.load(std::memory_order_relaxed);
}

uint64_t RequestsHandler::getSdpRejected() const
{
	return _sdpRejected.load(std::memory_order_relaxed);
}

void RequestsHandler::rejectSdp(const std::shared_ptr<SipMessage>& request, SipMessage::SdpVerdict verdict)
{
	_sdpRejected.fetch_add(1, std::memory_order_relaxed);
	const char* why = SipMessage::sdpVerdictText(verdict);

	// Only a request other than ACK takes a final response (RFC 3261 §17.1.1.3,
	// §8.2.6). A poison response or ACK is simply not acted on: not relayed, not
	// matched against a transaction, not used to advance a session.
	const bool isResponse = request->getStatusInfo().has_value();
	if (isResponse || request->getType() == SipMessageTypes::ACK)
	{
		queueLog("[SIP] SDP refused (" + std::string(why) + "), dropped: " +
			std::string(request->getHeader()) + " from " + std::string(request->getFromNumber()), true);
		return;
	}

	auto response = getMessageFromPool(*request);
	if (!response) return;   // pool exhausted: drop, peer retransmits (#101A)
	response->setHeader("SIP/2.0 488 Not Acceptable Here");
	response->clearBody();
	// Warning 399 (miscellaneous, RFC 3261 §20.43) with the reason, so the
	// refusal is diagnosable from the phone's SIP trace rather than a mystery 488.
	response->addHeader("Warning", "399 " + _localIp + " \"SDP refused: " + why + "\"");
	response->setVia(sipwire::viaWithReceived(request->getVia(), request->getSource()));
	_outbox.emplace_back(request->getSource(), std::move(response));
	queueLog("[SIP] SDP refused (" + std::string(why) + "), 488 to " +
		std::string(request->getFromNumber()) + " for " + std::string(request->getHeader()), true);
}

uint64_t RequestsHandler::getPacketsDropped() const
{
	return _packetsDropped.load(std::memory_order_relaxed);
}

std::vector<CallDetailRecord> RequestsHandler::getCallDetailRecords()
{
	std::lock_guard<std::mutex> lock(_snapshotMutex);
	return _snapshot.cdr;
}

std::string RequestsHandler::getPcapCapture()
{
	// Unlike the dashboard snapshot fields, the pcap ring isn't mirrored out to
	// _snapshot: it's populated directly under _mutex (handle()/drainOutbox()),
	// and serializing up to POCKETDIAL_PCAP_RING_SIZE small entries is cheap
	// enough to do inline rather than adding a second copy of the same data.
	std::lock_guard<std::mutex> lock(_mutex);
	return _pcapCapture.toPcapFile(_localIp, static_cast<uint16_t>(_serverPort));
}

std::vector<PcapCapture::TraceRecord> RequestsHandler::getTraceRecords()
{
	std::lock_guard<std::mutex> lock(_mutex);
	return _pcapCapture.traceRecords();
}

std::optional<RequestsHandler::ProvisioningInfo> RequestsHandler::findProvisioningInfo(
	const std::string& mac)
{
	std::lock_guard<std::mutex> lock(_mutex);
	for (const auto& d : _registrar.adoptedDevices())
	{
		if (d.mac == mac)
		{
			// Defense in depth (Issue #107): the .cfg served for this device
			// interpolates the extension into `key = value\r\n` lines, so a CR/LF in
			// it would inject config lines nobody wrote. Every path that adopts an
			// extension today goes through onRegister()'s isValidAor() gate, whose
			// charset excludes CR/LF -- this re-checks that invariant at the point of
			// use so provisioning does not silently depend on a gate three call layers
			// away. Fails closed: no info -> the endpoint 404s.
			//
			// Issue #163 addendum: same reasoning, for the reserved/emergency/PSTN-
			// shaped identity guard. onRegister() already refuses a REGISTER that
			// would adopt a device under 911, a service-adjacent virtual extension,
			// etc, but this recheck means provisioning does not silently depend on
			// that gate either -- a device record reaching this point under a name
			// that guard would refuse must not walk away with a working .cfg for it.
			if (!isValidAor(d.extension) || pbx::isReservedOrPstnAor(d.extension))
			{
				queueLog("Provisioning refused for " + mac +
					": adopted extension fails the AOR charset or identity guard", true);
				return std::nullopt;
			}
			const bool authRequired = (d.state == Registrar::DeviceState::Secured) ||
				(_registrar.getMode() == Registrar::Mode::Secure);
			return ProvisioningInfo{d.extension, authRequired};
		}
	}
	return std::nullopt;
}

void RequestsHandler::setDnd(const std::string& extension, bool on)
{
	std::vector<std::pair<bool, std::string>> localLogs;
	{
		std::lock_guard<std::mutex> lock(_mutex);
		_cfg.setDndLocked(extension, on);
		localLogs = std::move(_logQueue);
		_logQueue.clear();
	}

	for (const auto& log : localLogs)
	{
		if (log.first) std::cerr << log.second << '\n';
		else std::cout << log.second << '\n';
	}
}

std::vector<std::string> RequestsHandler::getDndExtensions()
{
	std::lock_guard<std::mutex> lock(_snapshotMutex);
	return _snapshot.dnd;
}

void RequestsHandler::setVoicemail(const std::string& extension, bool on)
{
	std::vector<std::pair<bool, std::string>> localLogs;
	{
		std::lock_guard<std::mutex> lock(_mutex);
		_cfg.setVoicemailEnabledLocked(extension, on);
		localLogs = std::move(_logQueue);
		_logQueue.clear();
	}

	for (const auto& log : localLogs)
	{
		if (log.first) std::cerr << log.second << '\n';
		else std::cout << log.second << '\n';
	}
}

std::vector<std::string> RequestsHandler::getVoicemailExtensions()
{
	std::lock_guard<std::mutex> lock(_snapshotMutex);
	return _snapshot.voicemail;
}

// ── Call forwarding (CFU/CFB/CFNA) ───────────────────────────────────────────

void RequestsHandler::setForward(const std::string& extension, const std::string& trigger, const std::string& target)
{
	std::vector<std::pair<bool, std::string>> localLogs;
	{
		std::lock_guard<std::mutex> lock(_mutex);
		_cfg.setForwardLocked(extension, trigger, target);
		localLogs = std::move(_logQueue);
		_logQueue.clear();
	}

	for (const auto& log : localLogs)
	{
		if (log.first) std::cerr << log.second << '\n';
		else std::cout << log.second << '\n';
	}
}

std::vector<std::tuple<std::string, std::string, std::string, std::string>> RequestsHandler::getForwards()
{
	std::lock_guard<std::mutex> lock(_snapshotMutex);
	return _snapshot.forwards;
}

// ── Ring / hunt groups ───────────────────────────────────────────────────────

void RequestsHandler::setE911Config(const std::string& exts, const std::string& callback,
	const std::string& location)
{
	std::vector<std::pair<bool, std::string>> localLogs;
	{
		std::lock_guard<std::mutex> lock(_mutex);
		_cfg.setE911Config(exts, callback, location);
		localLogs = std::move(_logQueue);
		_logQueue.clear();
	}

	for (const auto& log : localLogs)
	{
		if (log.first) std::cerr << log.second << '\n';
		else std::cout << log.second << '\n';
	}
}

std::tuple<std::string, std::string, std::string> RequestsHandler::getE911Config()
{
	std::lock_guard<std::mutex> lock(_mutex);
	const pbx::E911Config& c = _cfg.e911Config();
	return {pbx::joinMembers(c.notifyExts), c.callback, c.location};
}

void RequestsHandler::setRingGroup(const std::string& groupExt, const std::string& members, const std::string& mode)
{
	std::vector<std::pair<bool, std::string>> localLogs;
	{
		std::lock_guard<std::mutex> lock(_mutex);
		_cfg.setRingGroup(groupExt, members, mode);
		localLogs = std::move(_logQueue);
		_logQueue.clear();
	}

	for (const auto& log : localLogs)
	{
		if (log.first) std::cerr << log.second << '\n';
		else std::cout << log.second << '\n';
	}
}

std::vector<std::tuple<std::string, std::string, std::string>> RequestsHandler::getRingGroups()
{
	std::lock_guard<std::mutex> lock(_snapshotMutex);
	return _snapshot.ringGroups;
}

// Mirrors one of _cfg's five tables into the dashboard snapshot (Issue #77);
// see PbxFeatureConfig's class comment and RequestsHandler.hpp's _cfg member
// comment for why this indirection exists. Caller holds _mutex (this is
// invoked synchronously from inside _cfg's Locked mutation cores).
void RequestsHandler::refreshPbxConfigSnapshot(PbxFeatureConfig::Table t)
{
	std::lock_guard<std::mutex> snapLock(_snapshotMutex);
	switch (t)
	{
	case PbxFeatureConfig::Table::Dnd:
		_snapshot.dnd = _cfg.dndSnapshot();
		break;
	case PbxFeatureConfig::Table::Forwards:
		_snapshot.forwards = _cfg.forwardsSnapshot();
		break;
	case PbxFeatureConfig::Table::RingGroups:
		_snapshot.ringGroups = _cfg.ringGroupsSnapshot();
		break;
	case PbxFeatureConfig::Table::PageZones:
		_snapshot.pageZones = _cfg.pageZonesSnapshot();
		break;
	case PbxFeatureConfig::Table::DialRules:
		_snapshot.dialRules = _cfg.dialRulesSnapshot();
		break;
	case PbxFeatureConfig::Table::Voicemail:
		_snapshot.voicemail = _cfg.voicemailSnapshot();
		break;
	}
}

void RequestsHandler::setDialRule(const std::string& pattern, const std::string& action,
	const std::string& target, int stripDigits)
{
	std::vector<std::pair<bool, std::string>> localLogs;
	{
		std::lock_guard<std::mutex> lock(_mutex);
		_cfg.setDialRule(pattern, action, target, stripDigits);
		localLogs = std::move(_logQueue);
		_logQueue.clear();
	}

	for (const auto& log : localLogs)
	{
		if (log.first) std::cerr << log.second << '\n';
		else std::cout << log.second << '\n';
	}
}

std::vector<std::tuple<std::string, std::string, std::string, int>> RequestsHandler::getDialRules()
{
	std::lock_guard<std::mutex> lock(_snapshotMutex);
	return _snapshot.dialRules;
}

// ── Telephony-API credential slots (ported from drawbridge) ──────────────────
// See RequestsHandler.hpp's comment on this block for why these lock _mutex
// directly (like the setters above) rather than reading through the
// dashboard snapshot (like getDialRules() just above): nothing on the SIP hot
// path reads _tapiConfig yet, so there is no contention to shield against.

std::vector<TelephonyApiConfig::SlotView> RequestsHandler::getTelephonyConfigSlots()
{
	std::lock_guard<std::mutex> lock(_mutex);
	std::vector<TelephonyApiConfig::SlotView> views;
	views.reserve(TelephonyApiConfig::kSlots);
	for (size_t i = 0; i < TelephonyApiConfig::kSlots; ++i)
	{
		views.push_back(_tapiConfig.view(i));
	}
	return views;
}

TelephonyApiConfig::SlotView RequestsHandler::getTelephonyConfigSlot(size_t idx)
{
	std::lock_guard<std::mutex> lock(_mutex);
	return _tapiConfig.view(idx);
}

RequestsHandler::TestDialResult RequestsHandler::testDialSlot(size_t idx)
{
	AnchorClient* anchor = nullptr;
	std::string destination;
	{
		std::lock_guard<std::mutex> lock(_mutex);
		if (idx != _tapiConfig.activeSlot())
		{
			// Only the boot-selected slot has a live _anchorClient (provider
			// selection is boot-time-only — see anchorIsSynchronous()'s doc
			// comment); testing any other slot would either test the wrong
			// connection or silently no-op, so refuse instead.
			return TestDialResult{false, "", "this slot is not the active one — activate it and reboot first"};
		}
		if (!_anchorClient || !_anchorClient->isConnected())
		{
			return TestDialResult{false, "", "no anchor client connected"};
		}
		anchor = _anchorClient;
		destination = _tapiConfig.view(idx).routeDn;
	}

	// Deliberately outside _mutex: for a real (non-Loopback) provider, makeCall()/
	// dropCall() are blocking TLS HTTP round trips (same reasoning asyncMakeCall()'s
	// worker-thread wrapping documents) — holding the engine's one shared mutex
	// across that would stall SIP packet handling for the whole device. This is a
	// connectivity probe only: no session, no MediaBridge, no caller — dropCall()
	// runs immediately after a successful makeCall() rather than leaving a leg up.
	std::string ownLeg;
	if (!anchor->makeCall(destination, &ownLeg))
	{
		return TestDialResult{false, "", "anchor declined makeCall"};
	}
	if (!ownLeg.empty())
	{
		anchor->dropCall(ownLeg);
	}
	return TestDialResult{true, ownLeg, ""};
}

std::string RequestsHandler::setTelephonyConfigSlot(size_t idx, const TelephonyApiConfig::Slot& s, bool keepSecret)
{
	std::lock_guard<std::mutex> lock(_mutex);
	return _tapiConfig.setSlot(idx, s, keepSecret);
}

std::string RequestsHandler::setTelephonyConfigActiveSlot(size_t idx)
{
	std::lock_guard<std::mutex> lock(_mutex);
	return _tapiConfig.setActiveSlot(idx);
}

std::string RequestsHandler::clearTelephonyConfigSlot(size_t idx)
{
	std::lock_guard<std::mutex> lock(_mutex);
	return _tapiConfig.clearSlot(idx);
}

std::string RequestsHandler::clearAllTelephonyConfig()
{
	std::lock_guard<std::mutex> lock(_mutex);
	return _tapiConfig.clearAll();
}

// ── SBC mode (Issue #201) ─────────────────────────────────────────────────────

std::pair<bool, size_t> RequestsHandler::getSbcMode()
{
	std::lock_guard<std::mutex> lock(_mutex);
	return {_cfg.sbcEnabled(), _cfg.sbcRoute()};
}

std::string RequestsHandler::setSbcMode(bool enabled, size_t route)
{
	std::vector<std::pair<bool, std::string>> localLogs;
	std::string err;
	{
		std::lock_guard<std::mutex> lock(_mutex);
		if (enabled)
		{
			// Validate + activate BEFORE persisting the toggle, so a bad slot
			// index leaves SBC mode exactly as it was rather than "on" with a
			// route this build refused.
			err = _tapiConfig.setActiveSlot(route);
			if (err.empty())
			{
				_cfg.setSbcMode(true, route);
			}
		}
		else
		{
			// Disabling never touches the active slot -- the 555 anchor
			// extension or a manual Trunk dial-plan rule may still depend on
			// whichever slot is active independent of SBC mode.
			_cfg.setSbcMode(false, route);
		}
		localLogs = std::move(_logQueue);
		_logQueue.clear();
	}

	for (const auto& log : localLogs)
	{
		if (log.first) std::cerr << log.second << '\n';
		else std::cout << log.second << '\n';
	}
	return err;
}

// ── DID -> extension inbound routing (new) ────────────────────────────────────
// Same direct-_mutex rationale as the Telephony-API slots immediately above.

std::vector<DidMapping::Entry> RequestsHandler::getDidMappings()
{
	std::lock_guard<std::mutex> lock(_mutex);
	return _didMapping.list();
}

std::string RequestsHandler::setDidMapping(const std::string& did, const std::string& extension)
{
	std::lock_guard<std::mutex> lock(_mutex);
	return _didMapping.setMapping(did, extension);
}

std::string RequestsHandler::removeDidMapping(const std::string& did)
{
	std::lock_guard<std::mutex> lock(_mutex);
	return _didMapping.removeMapping(did);
}

std::string RequestsHandler::clearAllDidMappings()
{
	std::lock_guard<std::mutex> lock(_mutex);
	return _didMapping.clearAll();
}

void RequestsHandler::clearAllCallHistory()
{
	std::lock_guard<std::mutex> lock(_mutex);
	_cdr.clearAll();
}

// ── Registrar mode (STAGE 2) ──────────────────────────────────────────────────

void RequestsHandler::setRegistrarMode(RegistrarMode mode)
{
	std::vector<std::pair<bool, std::string>> localLogs;
	{
		std::lock_guard<std::mutex> lock(_mutex);
		_registrar.setMode(mode);
		localLogs = std::move(_logQueue);
		_logQueue.clear();
	}
	for (const auto& log : localLogs)
	{
		if (log.first) std::cerr << log.second << '\n';
		else std::cout << log.second << '\n';
	}
}

RequestsHandler::RegistrarMode RequestsHandler::getRegistrarMode() const
{
	// Lock-free read: the dashboard polls this; onRegister() branches on it on the
	// hot path. The Registrar's atomic guarantees a torn-free load.
	return _registrar.getMode();
}

// ── Device registry (STAGE 2: Learn-mode adoption) ────────────────────────────

void RequestsHandler::refreshDeviceSnapshot()
{
	// Caller holds _mutex. Mirror the Registrar's registry (including the volatile
	// online flags it tracks) into the dashboard snapshot.
	auto devices = _registrar.adoptedDevices();
	std::lock_guard<std::mutex> snapLock(_snapshotMutex);
	_snapshot.devices = std::move(devices);
}

void RequestsHandler::applyDeviceChange(Registrar::Change change)
{
	// Caller holds _mutex; takes _snapshotMutex internally.
	//
	// An online flip leaves the row set identical, so patching the flags in place
	// avoids rebuilding the vector and its two strings per device. That is the
	// common case by a wide margin — every registration and every lease expiry
	// flips a flag, and a post-reboot storm flips one per phone, which would
	// otherwise make the mirror cost O(devices) allocations per REGISTER.
	switch (change)
	{
		case Registrar::Change::None:
			return;
		case Registrar::Change::OnlineOnly:
		{
			std::lock_guard<std::mutex> snapLock(_snapshotMutex);
			_registrar.copyOnlineFlagsInto(_snapshot.devices);
			return;
		}
		case Registrar::Change::Structural:
			refreshDeviceSnapshot();
			return;
	}
}

std::vector<RequestsHandler::AdoptedDevice> RequestsHandler::getAdoptedDevices()
{
	std::lock_guard<std::mutex> lock(_snapshotMutex);
	return _snapshot.devices;
}

bool RequestsHandler::secureDevice(const std::string& macOrExt)
{
	std::vector<std::pair<bool, std::string>> localLogs;
	bool changed = false;
	{
		std::lock_guard<std::mutex> lock(_mutex);
		changed = _registrar.secure(macOrExt);
		applyDeviceChange(_registrar.consumeDevicesChange());
		localLogs = std::move(_logQueue);
		_logQueue.clear();
	}
	for (const auto& log : localLogs)
	{
		if (log.first) std::cerr << log.second << '\n';
		else std::cout << log.second << '\n';
	}
	return changed;
}

bool RequestsHandler::forgetDevice(const std::string& macOrExt)
{
	std::vector<std::pair<bool, std::string>> localLogs;
	bool removed = false;
	{
		std::lock_guard<std::mutex> lock(_mutex);
		removed = _registrar.forget(macOrExt);
		applyDeviceChange(_registrar.consumeDevicesChange());
		localLogs = std::move(_logQueue);
		_logQueue.clear();
	}
	for (const auto& log : localLogs)
	{
		if (log.first) std::cerr << log.second << '\n';
		else std::cout << log.second << '\n';
	}
	return removed;
}

// ── Outbound SIP MESSAGE (STAGE 2) ────────────────────────────────────────────

bool RequestsHandler::sendMessageTo(const std::string& ext, const std::string& text)
{
	std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>> localOutbox;
	bool sent = false;
	{
		std::lock_guard<std::mutex> lock(_mutex);

		auto client = findClient(ext);
		if (!client.has_value())
		{
			// Not registered → nothing to send to. Best-effort, no enqueue.
			return false;
		}

		const sockaddr_in& addr = client.value()->getAddress();
		std::string destIpPort = sipwire::addrToIpPort(addr);

		std::string activeIp = _localIp;
		std::string srcIpPort = activeIp + ":" + std::to_string(_serverPort);

		std::string callId  = IDGen::GenerateID(16) + "@" + activeIp;
		std::string branch  = "z9hG4bK" + IDGen::GenerateID(12);
		std::string fromTag = IDGen::GenerateID(9);

		// Bound the body so the whole datagram stays well under a typical MTU; a
		// notify is short by design.
		std::string body = text.size() > 512 ? text.substr(0, 512) : text;

		std::ostringstream ss;
		ss << "MESSAGE sip:" << ext << "@" << destIpPort << " SIP/2.0\r\n"
		   << "Via: SIP/2.0/UDP " << srcIpPort << ";branch=" << branch << "\r\n"
		   << "From: \"PocketDial\" <sip:" << pbx::kServicePbx << "@" << srcIpPort << ">;tag=" << fromTag << "\r\n"
		   << "To: <sip:" << ext << "@" << activeIp << ">\r\n"
		   << "Call-ID: " << callId << "\r\n"
		   << "CSeq: 1 MESSAGE\r\n"
		   << "Max-Forwards: 70\r\n"
		   << "User-Agent: pocket-dial\r\n"
		   << "Content-Type: text/plain\r\n"
		   << "Content-Length: " << body.size() << "\r\n\r\n"
		   << body;

		auto msg = getMessageFromPool(ss.str(), addr);
		if (!msg) return false;   // pool exhausted: drop, peer retransmits (#101A)
		msg->syncContentLength();
		_outbox.emplace_back(addr, std::move(msg));
		sent = true;

		// Drain into a local vector and dispatch outside the lock (no IO under lock).
		localOutbox = drainOutbox();
	}

	for (auto& [addr, msg] : localOutbox)
	{
		_onHandled(addr, std::move(msg));
	}
	return sent;
}

size_t RequestsHandler::getClientCount()
{
	std::lock_guard<std::mutex> lock(_snapshotMutex);
	return _snapshot.clients.size();
}

size_t RequestsHandler::getSessionCount()
{
	std::lock_guard<std::mutex> lock(_snapshotMutex);
	return _snapshot.sessions.size();
}

int RequestsHandler::getConferenceLegs()
{
	std::lock_guard<std::mutex> lock(_mutex);
	return _conference ? _conference->legCount() : 0;
}

void RequestsHandler::queueDtmfDigit(std::string_view callId, char digit)
{
	if (digit == '\0' || callId.empty()) return;

	// Stamp at CAPTURE, not at drain. The press may wait up to a tick for the SIP
	// thread, and DtmfAccum::TIMEOUT_MS is the user's inter-digit budget — if the
	// timestamp came from drain time, the drain cadence would quietly consume
	// part of it and a slowly-dialled feature code would reset mid-sequence.
	DtmfPress press;
	press.digit       = digit;
	press.source      = static_cast<uint8_t>(DtmfFeatureCodes::DigitSource::Rfc4733);
	press.arrivedTick = DtmfFeatureCodes::nowTickMs();
	const size_t n = callId.size() < sizeof(press.callId)
		? callId.size() : sizeof(press.callId) - 1;
	std::memcpy(press.callId, callId.data(), n);
	press.callId[n] = '\0';

	{
		std::lock_guard<std::mutex> lk(_dtmfInboxMutex);
		if (_dtmfInboxCount >= _dtmfInbox.size())
		{
			// Full: drop the OLDEST press and keep the newest. If the SIP thread
			// has fallen this far behind, the stale digits at the front are the
			// ones least likely to still complete a sequence the user is typing.
			// Dropping rather than blocking is the whole point — a stalled RTP
			// task costs the call's audio, a dropped digit costs one keypress.
			std::move(_dtmfInbox.begin() + 1, _dtmfInbox.end(), _dtmfInbox.begin());
			--_dtmfInboxCount;
			_dtmfDropped.fetch_add(1, std::memory_order_relaxed);
		}
		_dtmfInbox[_dtmfInboxCount++] = press;
	}
}

uint64_t RequestsHandler::dtmfDigitsDropped() const
{
	return _dtmfDropped.load(std::memory_order_relaxed);
}

void RequestsHandler::drainDtmfInbox()
{
	// One press at a time: take the front under the small lock, release it, then
	// dispatch. Two properties this buys, both of which matter here.
	//
	// The producer's lock is never held across a feature-code action — those
	// enqueue SIP messages and touch the config store, and stalling a real-time
	// media task for that long is the thing this whole ring exists to avoid.
	//
	// And nothing large lands on the stack. Lifting the whole batch into a local
	// array first would have been simpler to read, but that array is ~2.2 KB and
	// this runs inside handle(), on a SIP task with an 8 KB stack
	// (esp_main.cpp:438) that is already several frames deep by the time it gets
	// here. Burning a quarter of it on a convenience copy is not a trade worth
	// making for a loop that is almost always zero or one iterations.
	//
	// Bounded by the ring's depth rather than by "until empty" so a producer that
	// is somehow outpacing us cannot hold the SIP thread in this loop; whatever
	// arrives mid-drain simply waits for the next pass.
	for (size_t guard = 0; guard < _dtmfInbox.size(); ++guard)
	{
		DtmfPress p;
		{
			std::lock_guard<std::mutex> lk(_dtmfInboxMutex);
			if (_dtmfInboxCount == 0) break;
			p = _dtmfInbox[0];
			--_dtmfInboxCount;
			// Shift the remainder down. At most POCKETDIAL_DTMF_INBOX small
			// trivially-copyable records, and in practice one or two — cheaper
			// than the head/tail bookkeeping a true circular buffer would need,
			// and far easier to read.
			for (size_t i = 0; i < _dtmfInboxCount; ++i)
			{
				_dtmfInbox[i] = _dtmfInbox[i + 1];
			}
		}

		// The dialog may have ended between capture and now — the call hung up
		// while a digit was in flight. Drop it silently rather than creating an
		// accumulator for a dead Call-ID, which sweepStale() would only have to
		// reap later.
		if (!findSession(p.callId)) continue;
		_dtmf.onDigit(p.callId, p.digit,
			static_cast<DtmfFeatureCodes::DigitSource>(p.source),
			p.arrivedTick, nullptr);
	}
}

size_t RequestsHandler::getClientTransactionCount()
{
	std::lock_guard<std::mutex> lock(_mutex);
	return _txLayer.activeClientTransactions();
}

size_t RequestsHandler::getServerTransactionCount()
{
	std::lock_guard<std::mutex> lock(_mutex);
	return _txLayer.activeServerTransactions();
}

void RequestsHandler::tick()
{
	auto now = std::chrono::steady_clock::now();
	if (now - _lastTick < std::chrono::seconds(1))
	{
		return;
	}
	_lastTick = now;

	std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>> localOutbox;
	std::vector<std::pair<bool, std::string>> localLogs;
	{
		std::lock_guard<std::mutex> lock(_mutex);
		_outbox.clear();
		// No inbound message owns a tick() pass. Cleared here rather than only at
		// the end of handle() because handle() has early returns between setting
		// it and draining (the INFO pool-exhaustion path, for one), and a stale
		// pointer left behind would silently suppress retransmit tracking for
		// whatever pooled SipMessage next lands on that address.
		_passThroughMsg = nullptr;

		// The only drain a conference gets when nobody is signalling: an 888 leg
		// carries RTP but no SIP, so feature codes pressed mid-conference arrive
		// on this path alone.
		drainDtmfInbox();

		sweepExpired();

		// AnchorClient::tick(): "periodic, non-blocking maintenance pump ... (<=1 Hz)"
		// per its doc comment. Loopback's is a no-op; a real anchor uses this for
		// TLS re-warm / reconnect bookkeeping without blocking the SIP thread.
		if (_anchorClient)
		{
			_anchorClient->tick();
		}

		// RFC 3261 §17: retransmit timed-out INVITE forks and free completed slots.
		_txLayer.sweep(now);
		// RFC 4028: BYE sessions that have exceeded their session-expires timer.
		sweepSessionTimers(now);
		// BLF subscription expiry.
		_blf.sweepExpired();
		// Call-park timeout: ring back the parker or BYE the parked party.
		_park.sweep(now);

		// Issue #164: a trunk INVITE that never got a final response. Without
		// this the no-answer deadline placeCall() arms is never read by
		// anything, so a silent SBC leaks the dialog slot, the relay pair and
		// the handset session, with the phone ringing forever -- the trunk
		// machine cannot time itself out, it has no clock of its own.
		_sipTrunk.sweep(now);

		// Issue #164: keep the SBC address warm. routeTrunkCall() deliberately
		// uses the CACHE-ONLY lookup(), because resolving on the SIP thread is
		// the blocking getaddrinfo that TrunkResolver exists to keep off it.
		// That makes something else responsible for ever populating the cache,
		// and this is it: resolve() returns immediately and hands the work to
		// the resolver's own task. Without it an FQDN host never resolves at
		// all and only a dotted-quad trunk can place a call.
		if (_sipTrunk.config().valid())
		{
			sockaddr_in unusedAddr{};
			_trunkResolver.resolve(_sipTrunk.config().transportHost(),
				_sipTrunk.config().transportPort(), unusedAddr, now);
		}

		// Belt-and-suspenders (Fix #4): drop DTMF accumulators whose dialog is gone,
		// in case a teardown path bypassed endCall(). Bounded by the small session pool.
		_dtmf.sweepStale();

		// Issue #246: advance Deposit voicemail legs (greeting -> recording)
		// and enforce the wall-clock recording deadline.
		sweepVoicemailLegs(now);

		// No-answer timers (CFNA + hunt-group progression, plus the anchor
		// no-answer/ACK-deadline reap below). Poll the armed sessions and act on
		// any that have run past their ring deadline without connecting. Collected
		// first so we don't mutate _sessions while iterating it.
		std::vector<std::string> expiredCallIds;
		for (const auto& [callID, session] : _sessions)
		{
			// A CONNECTED outbound anchor whose ACK deadline (ANCHOR_ACK_TIMEOUT)
			// expired is an abandoned call — the handset never ACKed our 200 OK
			// (bridged too late, or the phone already gave up) — reap it too so
			// its upstream leg + bridge don't zombie forever.
			const bool connectedAbandonedAnchor =
				session->getState() == Session::State::Connected &&
				session->isAnchor() && !session->isAnchorInbound();
			if (session->isRingExpired(now) &&
			    (session->getState() == Session::State::Invited || connectedAbandonedAnchor))
			{
				expiredCallIds.push_back(callID);
			}
		}
		for (const auto& callID : expiredCallIds)
		{
			auto sit = _sessions.find(callID);
			if (sit == _sessions.end()) continue;
			auto session = sit->second;
			session->clearRingTimer();

			if (session->isAnchorInbound())
			{
				// Inbound anchor call: no extension picked up. CANCEL every still-
				// ringing forked INVITE (server is UAC), drop the upstream leg, and
				// end the session. No leg answered (state is Invited), so
				// pendingTargets still holds them all.
				for (const auto& target : session->getPendingTargets())
				{
					auto cancel = buildInboundCancelTo(session, target);
					if (cancel) _outbox.emplace_back(target->getAddress(), std::move(cancel));
				}
				asyncDropCall(session->getAnchorParticipantId());
				session->setAnchorLegReleased();   // #379: endCall() must not drop it again
				queueLog("[Telephony] Inbound: no answer from " +
				         std::to_string(session->getPendingTargets().size()) + " extension(s) — cancelled");
				endCall(callID, session->getAnchorParticipantId(), "", "inbound no answer");
				continue;
			}

			if (session->isAnchor())
			{
				// Plain OUTBOUND anchor call that expired — either the far end never
				// connected it (still Invited) or the handset never ACKed our 200
				// (Connected but abandoned). Either way DROP the upstream leg + free
				// its media bridge so it doesn't linger as a zombie (which erodes the
				// concurrent-call budget and otherwise needs a manual kill). 503 the
				// caller only while it's still ringing — a Connected-abandoned
				// handset is already gone, so there's no one to answer.
				const std::string part = session->getAnchorParticipantId();
				MediaBridge* b = bridgeForParticipant(part);
				if (!b)
				{
					for (auto& mb : _mediaBridges)
					{
						if (mb.isForCallId(callID)) { b = &mb; break; }
					}
				}
				if (b) b->stopBridge();
				if (!part.empty()) asyncDropCall(part);
				session->setAnchorLegReleased();   // #379: endCall() must not drop it again
				const bool stillRinging = (session->getState() == Session::State::Invited);
				if (stillRinging && session->getInviteMessage())
				{
					auto invite = session->getInviteMessage();
					auto resp = getMessageFromPool(*invite);
					if (resp)
					{
						// 480, not 503. The far end rang and nobody picked up — that is
						// a no-answer, not a server fault. On this path 503 already
						// carries a specific and DIFFERENT meaning (capacity refusal
						// above, and refuseRingingAnchor's makeCall/worker failures),
						// while the sibling no-answer teardown — hunt-group exhaustion,
						// below — already answers 480. A UAS 503 additionally invites
						// upstream failover/blacklist behaviour that a plain no-answer
						// must never trigger.
						resp->setHeader("SIP/2.0 480 Temporarily Unavailable");
						resp->clearBody();
						resp->setContact(buildContact(std::string(invite->getToNumber())));
						_outbox.emplace_back(invite->getSource(), std::move(resp));
					}
				}
				queueLog(std::string("[Telephony] anchor call reaped (no ") + (stillRinging ? "answer" : "ACK") +
				         ") — dropped leg " + part);
				endCall(callID, session->getSrc() ? session->getSrc()->getNumber() : "", part, "anchor reap");
				continue;
			}

			if (session->isHunt())
			{
				// Advance to the next hunt member; CANCEL the member that timed out.
				for (const auto& t : session->getPendingTargets())
				{
					auto invite = session->getInviteMessage();
					if (invite)
					{
						auto cancel = _forker.buildCancel(invite, t);
						if (cancel) _outbox.emplace_back(t->getAddress(), std::move(cancel));
					}
				}
				if (!_forker.huntRingNext(session))
				{
					// List exhausted: 480 to the caller and tear down.
					auto invite = session->getInviteMessage();
					if (invite && session->getSrc())
					{
						auto resp = getMessageFromPool(*invite);
						if (!resp) continue;   // pool exhausted: skip this session's 480 (#101A)
						resp->setHeader(SipMessageTypes::UNAVAILABLE);
						resp->clearBody();
						resp->setContact(buildContact(session->getGroupExt()));
						_outbox.emplace_back(invite->getSource(), std::move(resp));
						endCall(callID, session->getSrc()->getNumber(), session->getGroupExt(), "hunt group no answer");
					}
				}
			}
			else
			{
				// CFNA: CANCEL the original callee leg and INVITE the no-answer target,
				// or (Issue #246) answer locally as voicemail.
				auto invite = session->getInviteMessage();
				auto dest = session->getDest();
				auto src = session->getSrc();
				std::string cfna = session->getNoAnswerTarget();
				if (invite && src && !cfna.empty())
				{
					if (cfna == pbx::kVoicemailForwardSentinel)
					{
						// Issue #246: this is a forked-dialog hazard, not a UX nicety
						// (RFC 3261 S13.2.2.4) -- the callee's phone is still
						// ringing on this exact Call-ID; if it answers after we've
						// already sent our own 200 OK, the caller's UA gets two
						// 2xx responses with different To-tags for one INVITE.
						// CANCEL it BEFORE answering, using a freshly looked-up
						// client rather than `dest` (which is null here by
						// construction -- dest is only populated once someone
						// answers, and CFNA only fires because nobody did; relying
						// on `dest` is the pre-existing gap that leaves the
						// original callee ringing on ordinary CFNA today).
						auto callee = findClient(invite->getToNumber());
						if (callee.has_value())
						{
							auto cancel = _forker.buildCancel(invite, callee.value());
							if (cancel) _outbox.emplace_back(callee.value()->getAddress(), std::move(cancel));
						}
						// Noted, not fixed here (found in review): endCall() here
						// writes a CDR ("no answer (voicemail)"), then
						// answerVoicemailDeposit() re-inserts the same Call-ID under
						// a new session -- the eventual BYE writes a SECOND CDR for
						// what a caller experiences as one call. The existing CFNA
						// redirect path has the identical double-record shape, so
						// this matches established behavior rather than introducing
						// a new one; worth knowing when the mailbox CDR work lands.
						std::string depositExt(invite->getToNumber());
						endCall(callID, src->getNumber(), depositExt, "no answer (voicemail)");
						answerVoicemailDeposit(invite, src, depositExt);
					}
					else
					{
						if (dest)
						{
							auto cancel = _forker.buildCancel(invite, dest);
							if (cancel) _outbox.emplace_back(dest->getAddress(), std::move(cancel));
						}
						queueLog("CFNA: no answer, forwarding -> " + cfna);
						endCall(callID, src->getNumber(), std::string(invite->getToNumber()), "no answer (CFNA)");
						_forker.redirectInvite(invite, src, cfna);
					}
				}
			}
		}

		// Issue #280: a connected (talking OR held) anchor call whose media
		// bridge has racked up too many consecutive AnchorClient::writeAudio()
		// failures (MediaBridge::isAudioDegraded()) gets torn down here --
		// same shape as the no-answer/ACK-deadline reap just above, but
		// triggered by the write path itself rather than a ring timer. This is
		// the propagation #280 asked for: writeAudio() already returned false
		// on every failed write, but nothing ever acted on it, so a leg with a
		// genuinely broken audio path pumped MoH/handset audio into a dead
		// connection for the rest of the call instead of tearing down.
		//
		// Both Connected and Held are checked, unlike the no-answer/ACK-deadline
		// reap above (which is Connected-only because its own trigger, an
		// unACKed 200 OK, cannot happen once a call has been put on hold). #279's
		// actual failure mode -- MoH playing into a dead connection -- is a HELD
		// call by definition, so excluding Held here would miss the exact case
		// this is also meant to close.
		//
		// Not excluding isAnchorInbound() either, unlike that same reap: its
		// exclusion is about a pre-answer concern (an inbound call's own
		// ACK-timeout semantics don't apply the same way), not about how this
		// bridge writes audio once connected -- MediaBridge::writeAudio()
		// failures are identical for both call directions past that point.
		//
		// Collected first, same reasoning as expiredCallIds above: endCall()
		// erases from _sessions, so acting while iterating it would invalidate
		// the iterator.
		std::vector<std::string> degradedAnchorCallIds;
		for (const auto& [callID, session] : _sessions)
		{
			if (!session->isAnchor()) continue;
			if (session->getState() != Session::State::Connected &&
			    session->getState() != Session::State::Held) continue;
			MediaBridge* b = bridgeForParticipant(session->getAnchorParticipantId());
			if (!b)
			{
				for (auto& mb : _mediaBridges)
				{
					if (mb.isForCallId(callID)) { b = &mb; break; }
				}
			}
			if (b && b->isAudioDegraded())
			{
				degradedAnchorCallIds.push_back(callID);
			}
		}
		for (const auto& callID : degradedAnchorCallIds)
		{
			auto sit = _sessions.find(callID);
			if (sit == _sessions.end()) continue;
			auto session = sit->second;
			const std::string part = session->getAnchorParticipantId();
			MediaBridge* b = bridgeForParticipant(part);
			if (!b)
			{
				for (auto& mb : _mediaBridges)
				{
					if (mb.isForCallId(callID)) { b = &mb; break; }
				}
			}
			if (b) b->stopBridge();
			if (!part.empty()) asyncDropCall(part);
			session->setAnchorLegReleased();   // #379: endCall() must not drop it again
			queueLog("[Telephony] anchor call torn down: audio write repeatedly failed — dropped leg " + part);

			// Issue #279: this branch dropped the ANCHOR side (asyncDropCall) and
			// erased the board's own bookkeeping (endCall, below) but never told
			// the LOCAL HANDSET anything. From the phone's point of view the call
			// simply never ends -- desmo's live repro was exactly this: the
			// Yealink still showed the call live and a later resume attempt drew
			// 481 Call/Transaction Does Not Exist, because the board had already
			// silently forgotten a call it never said goodbye to.
			//
			// buildServerBye()/_outbox is the same mechanism sweepSessionTimers()
			// (:8955) and forceDisconnect() (:7068) already use for exactly this
			// kind of server-initiated teardown -- a message-pool build plus an
			// enqueue, not a fresh heap allocation, so this does not reintroduce
			// the allocate-at-the-worst-moment problem #279 is named after. It is
			// still only a BEST EFFORT: the real socket transmit happens later,
			// at the _outbox drain (:9079), and can still fail under severe DRAM
			// exhaustion the way any outbound packet can (#278/#328). What this
			// closes is the far more common gap above: the code path that never
			// attempted the BYE at all, independent of whether transmission would
			// have succeeded.
			//
			// The local handset is whichever leg is NOT the anchor participant --
			// same direction split CDR attribution just below already uses.
			// getDialogFrom()/getDialogTo() are the captured dialog headers, and
			// which one plays which role depends on which side of the captured
			// dialog the handset is: for an inbound anchor call the handset is
			// the ORIGINAL callee (the "dest" role sweepSessionTimers() sends
			// From=dFrom/To=dTo to); for outbound the handset is the ORIGINAL
			// caller (the "src" role sweepSessionTimers() sends From=dTo/To=dFrom
			// to, swapped). Same #72 guard as both sibling functions: an empty
			// From or To is a malformed BYE phones will drop, so skip rather than
			// send garbage.
			const std::string& dFrom = session->getDialogFrom();
			const std::string& dTo   = session->getDialogTo();

			// CDR src/dest convention differs by direction (same as the no-answer
			// reap above splits it): outbound treats the local extension as src
			// and the anchor leg as dest; inbound treats the anchor participant
			// as src and the (already-answered, since this call is Connected/
			// Held) local extension as dest.
			if (session->isAnchorInbound())
			{
				auto handset = session->getDest();
				if (handset && !dFrom.empty() && !dTo.empty())
				{
					auto bye = buildServerBye(handset->getNumber(), handset->getAddress(),
						callID, dFrom, dTo);
					if (bye) _outbox.emplace_back(handset->getAddress(), std::move(bye));
				}
				endCall(callID, part, handset ? handset->getNumber() : "",
					"anchor audio write failure");
			}
			else
			{
				auto handset = session->getSrc();
				if (handset && !dFrom.empty() && !dTo.empty())
				{
					auto bye = buildServerBye(handset->getNumber(), handset->getAddress(),
						callID, dTo, dFrom);
					if (bye) _outbox.emplace_back(handset->getAddress(), std::move(bye));
				}
				endCall(callID, handset ? handset->getNumber() : "", part,
					"anchor audio write failure");
			}
		}

		// Reap ORPHANED media bridges — active but with NO owning anchor session.
		// Under a concurrent burst a bridge can outlive its session (a session
		// reaped/ended while its bridge teardown didn't match, or an Answered
		// landing just after its session was reaped). The session-based reaper
		// above can't see these — they'd pump audio to a dead handset forever,
		// hold the per-call RTP/TLS sockets, and (until dropped) keep the
		// upstream leg up. Drop the leg + free the bridge. Safe at 1 Hz: a
		// legitimate bridge is bound to its session under this same _mutex (the
		// CallEvent::Answered handler / onInboundAnchorOk), so an unowned active
		// bridge here is a real orphan, not a race.
		for (auto& b : _mediaBridges)
		{
			if (!b.isActive()) continue;
			const std::string bpart = b.participantId();
			const std::string bcall = b.callId();
			bool owned = false;
			for (const auto& [cid, s] : _sessions)
			{
				if (!s->isAnchor()) continue;
				if ((!bcall.empty() && cid == bcall) ||
				    (!bpart.empty() && s->getAnchorParticipantId() == bpart))
				{
					owned = true;
					break;
				}
			}
			if (!owned)
			{
				if (!bpart.empty())
				{
					if (anchorIsSynchronous() && _anchorClient) _anchorClient->dropCall(bpart);
					else asyncDropCall(bpart);
				}
				b.stopBridge();
				queueLog("[Telephony] reaped orphaned media bridge (no session) leg " + bpart);
			}
		}

#if !defined(ESP_PLATFORM) && !defined(ESP32)
		// Join+erase any asyncMakeCall/asyncDropCall/asyncAnswerCall host worker
		// that has finished, so the vector tracks in-flight calls rather than
		// growing without bound over the object's life.
		reapAnchorWorkers();
#endif

		// Sweep rate-limit buckets older than 60 seconds (Issue #58). The bucket map
		// now lives under _rateMutex (so per-packet admission never serializes on the
		// big _mutex), so take it here too. Nesting order is _mutex → _rateMutex;
		// handle() only ever holds them disjointly, so there is no deadlock.
		{
			std::lock_guard<std::mutex> rlock(_rateMutex);
			for (auto rit = _rateBuckets.begin(); rit != _rateBuckets.end(); )
			{
				if (now - rit->second.last > std::chrono::seconds(60))
				{
					rit = _rateBuckets.erase(rit);
				}
				else
				{
					++rit;
				}
			}
		}

		for (auto& client : _clientPool)
		{
			if (client->getNumber().empty()) continue;
			if (now - client->getLastPingTime() >= std::chrono::seconds(5))
			{
				auto ping = buildOptionsPing(client);
				// Stamp the ping time only once one actually exists. Stamping first
				// would re-arm the interval gate for a ping that was never sent, so
				// a refusal would cost a whole keepalive interval instead of being
				// retried on the next tick — worst behavior exactly when the box is
				// already overloaded (#101A).
				if (ping)
				{
					client->setLastPingTime(now);
					_outbox.emplace_back(client->getAddress(), std::move(ping));
				}
			}
		}

		// Register-beep timeouts: CANCEL unanswered beep INVITEs and free overdue
		// slots. Done here, under _mutex, enqueuing to _outbox; the actual sendto()
		// happens after the lock is dropped.
		_beeper.sweep(now);

		// Build snapshot under registrar mutex lock, then save it under snapshot mutex lock
		RegistrarSnapshot nextSnapshot;
		nextSnapshot.packetsProcessed = _packetsProcessed.load(std::memory_order_relaxed);
		nextSnapshot.packetsDropped = _packetsDropped.load(std::memory_order_relaxed);
		for (const auto& client : _clientPool)
		{
			if (client->getNumber().empty()) continue;
			const auto& addr = client->getAddress();
			std::string ipPort = sipwire::addrToIpPort(addr);
			nextSnapshot.clients.emplace_back(client->getNumber(), ipPort);
		}

		nextSnapshot.sessions.reserve(_sessions.size());
		for (const auto& [callID, session] : _sessions)
		{
			std::string caller = session->getSrc() ? session->getSrc()->getNumber() : "?";
			std::string callee = session->getDest() ? session->getDest()->getNumber() : "?";

			int durationSec = 0;
			if (session->getState() == Session::State::Connected)
			{
				durationSec = static_cast<int>(std::chrono::duration_cast<std::chrono::seconds>(
					now - session->getStartTime()).count());
			}
			nextSnapshot.sessions.emplace_back(caller, callee, sessionStateToString(session->getState()), durationSec);
		}

		// CDR view: newest-first copy of the ring into the snapshot.
		nextSnapshot.cdr = _cdr.snapshot();

		// DND view: extensions currently in DND.
		nextSnapshot.dnd = _cfg.dndSnapshot();

		// Call-forward view.
		nextSnapshot.forwards = _cfg.forwardsSnapshot();

		// Ring/hunt-group view.
		nextSnapshot.ringGroups = _cfg.ringGroupsSnapshot();

		// Dial-plan rules (Issue #69), in table order. Rebuilt from _cfg's dial
		// plan here alongside ringGroups rather than mirrored out of band like
		// pageZones, so the snapshot swap below can never blank or re-order them.
		nextSnapshot.dialRules = _cfg.dialRulesSnapshot();

		// Parked calls view: {orbit, parkedExt, parker, secondsParked}. This full
		// rebuild already reflects anything _park.sweep() just did above, so clear
		// the dirty flag here rather than leaving it to trigger a redundant mirror
		// on the next packet.
		nextSnapshot.parkedCalls = _park.snapshotRows(now, /*onlyParked=*/true);
		_park.consumeParkChanged();

		{
			std::lock_guard<std::mutex> snapLock(_snapshotMutex);
			// `devices` and `pageZones` are NOT rebuilt above: they are mirrored out
			// of band (applyDeviceChange on a registry change, and the page-zone
			// config path) because their sources only move on an admin action or a
			// REGISTER. Carry them across the swap — assigning a fresh snapshot over
			// the old one would blank both every tick, so the dashboard's adopted
			// devices and paging zones would flash empty a second after any update
			// and stay empty until the next change.
			nextSnapshot.devices   = std::move(_snapshot.devices);
			nextSnapshot.pageZones = std::move(_snapshot.pageZones);
			_snapshot = std::move(nextSnapshot);
		}

		localOutbox = drainOutbox();

		localLogs = std::move(_logQueue);
		_logQueue.clear();
	}

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

std::optional<std::shared_ptr<SipClient>> RequestsHandler::findClientByAddress(const sockaddr_in& addr)
{
	for (auto& client : _clientPool)
	{
		if (client->getNumber().empty()) continue;
		if (client->getAddress().sin_addr.s_addr == addr.sin_addr.s_addr &&
			client->getAddress().sin_port == addr.sin_port)
		{
			return client;
		}
	}
	return {};
}

std::shared_ptr<SipMessage> RequestsHandler::buildOptionsPing(const std::shared_ptr<SipClient>& client)
{
	std::string clientNum = client->getNumber();

	std::string destIpPort = sipwire::addrToIpPort(client->getAddress());

	std::string activeIp = _localIp;
	std::string srcIpPort = activeIp + ":" + std::to_string(_serverPort);

	std::string callId = IDGen::GenerateID(16) + "@" + activeIp;
	std::string branch = "z9hG4bK" + IDGen::GenerateID(12);
	std::string fromTag = IDGen::GenerateID(9);

	std::ostringstream ss;
	ss << "OPTIONS sip:" << clientNum << "@" << destIpPort << " SIP/2.0\r\n"
	   << "Via: SIP/2.0/UDP " << srcIpPort << ";branch=" << branch << "\r\n"
	   << "To: <sip:" << clientNum << "@" << destIpPort << ">\r\n"
	   << "From: <sip:" << pbx::kServiceServer << "@" << srcIpPort << ">;tag=" << fromTag << "\r\n"
	   << "Call-ID: " << callId << "\r\n"
	   << "CSeq: 1 OPTIONS\r\n"
	   << "Max-Forwards: 70\r\n"
	   << "User-Agent: pocket-dial\r\n"
	   << "Content-Length: 0\r\n\r\n";

	return getMessageFromPool(ss.str(), client->getAddress());
}

std::shared_ptr<SipClient> RequestsHandler::allocateClient(std::string number, sockaddr_in address, int expiresSeconds)
{
	// Re-REGISTER: find existing slot by number and refresh it in-place
	for (auto& client : _clientPool)
	{
		if (client->getNumber() == number)
		{
			queueLog("Re-registered: " + number);
			client->reset(number, address, expiresSeconds);
			return client;
		}
	}

	// New client: find the first free slot
	for (auto& client : _clientPool)
	{
		if (client->getNumber().empty())
		{
			queueLog("New Client: " + number);
			client->reset(std::move(number), address, expiresSeconds);
			return client;
		}
	}

	// No free slots! Evict the oldest expired client
	auto now = std::chrono::steady_clock::now();
	for (auto& client : _clientPool)
	{
		if (client->isExpired(now))
		{
			client->reset(std::move(number), address, expiresSeconds);
			return client;
		}
	}

	// Out of space!
	return nullptr;
}

std::shared_ptr<Session> RequestsHandler::allocateSession(std::string callID, std::shared_ptr<SipClient> src)
{
	for (auto& session : _sessionPool)
	{
		const std::string& slotId = session->getCallID();
		if (slotId.empty() || _sessions.find(slotId) == _sessions.end())
		{
			session->reset(std::move(callID), src);
			return session;
		}
	}
	return nullptr;
}

bool RequestsHandler::ipAllowed(const sockaddr_in& src) const
{
	if (_allowMask == 0) return true; // No allowlist configured
	uint32_t ip = ntohl(src.sin_addr.s_addr);
	return (ip & _allowMask) == _allowNet;
}

bool RequestsHandler::allowPacket(const sockaddr_in& src)
{
	auto now = std::chrono::steady_clock::now();
	uint32_t ip = src.sin_addr.s_addr; // Key by raw network-byte-order IP

	auto it = _rateBuckets.find(ip);
	if (it == _rateBuckets.end())
	{
		if (_rateBuckets.size() >= 256)
		{
			// Fail-safe drop if maximum buckets exceeded
			return false;
		}
		// New bucket: burst 40, sustained 20 pkt/s
		_rateBuckets[ip] = { 40.0, now };
		return true;
	}

	auto& bucket = it->second;
	double elapsedSec = std::chrono::duration<double>(now - bucket.last).count();
	bucket.last = now;

	// Replenish tokens (sustained rate = 20 tokens/sec)
	bucket.tokens = (std::min)(40.0, bucket.tokens + elapsedSec * 20.0);

	if (bucket.tokens >= 1.0)
	{
		bucket.tokens -= 1.0;
		return true;
	}

	return false; // Denied (Rate limit exceeded)
}

bool RequestsHandler::isValidAor(std::string_view s) const
{
	// Issue #194: length bound added alongside the charset check below -- see
	// kMaxAorLen's comment for why 64 and why this matters (unbounded heap
	// growth inside CdrRing's fixed-footprint slots). Charset-only until now.
	if (s.empty() || s.size() > kMaxAorLen) return false;
	for (char c : s)
	{
		// Alnum + RFC 3261 user-part punctuation we accept, plus '*' and '#' so star/pound
		// feature codes (e.g. *55) are dialable AORs. Tab/newline stay excluded, which the NVS
		// blob persistence relies on as field/record delimiters.
		if (!std::isalnum(static_cast<unsigned char>(c)) &&
			c != '.' && c != '-' && c != '_' && c != '+' &&
			c != '*' && c != '#')
		{
			return false;
		}
	}
	return true;
}

void RequestsHandler::queueLog(std::string msg, bool isError)
{
	_logQueue.push_back({isError, std::move(msg)});
}

// ── NVS persistence ────────────────────────────────────────────────────────────
//
// The PBX-config tables (forwards / ring groups / page zones / dial plan:
// loadPbxConfig, persistForwards, persistRingGroups, persistPageZones,
// persistDialPlan) now live on PbxFeatureConfig (see _cfg), and the CDR ring
// (load/persist, its own NVS namespace and record shape) now lives on CdrRing
// (see _cdr) — both still no-ops on host.

// ── Registrar mode + device registry persistence (STAGE 2) ───────────────────

// ── Task 2B/2C: admin extension identity + DTMF digit-collection state machine
// + CLASS service codes, now on DtmfFeatureCodes (see _dtmf) ──────────────────

std::string RequestsHandler::getAdminExt() const
{
	return _dtmf.adminExt();
}

// ── File-scope static helpers ─────────────────────────────────────────────────

static bool sameAddress(const sockaddr_in& a, const sockaddr_in& b)
{
	return a.sin_addr.s_addr == b.sin_addr.s_addr && a.sin_port == b.sin_port;
}

// Forward to the shared header helper (see SipHeaderUtil.hpp) — kept as a
// file-static name so the many call sites in this TU stay unchanged.
static std::string stripHeaderName(std::string_view h)
{
	return siphdr::stripHeaderName(h);
}

// ── Anchored-leg (555) re-INVITE/UPDATE — issue #218 ─────────────────────────
// See the declaration's doc comment (RequestsHandler.hpp) for the full "why":
// the board is the UAS on this leg, so a re-INVITE/UPDATE here is answered,
// not relayed. Shared by onReinvite() and onUpdate(), whose SDP-bearing path
// hits the identical case.
bool RequestsHandler::answerAnchorReinvite(const std::shared_ptr<SipMessage>& data,
	const std::shared_ptr<Session>& session, const std::shared_ptr<SipClient>& src)
{
	const std::string callIdStr(data->getCallID());
	MediaBridge* bridge = nullptr;
	for (auto& b : _mediaBridges)
	{
		if (b.isForCallId(callIdStr)) { bridge = &b; break; }
	}
	if (!bridge)
	{
		// Bridge already torn down (a race with teardown) -- nothing to answer
		// with. 481 is the honest response: the dialog this request names does
		// not have a media leg behind it any more.
		auto response = getMessageFromPool(*data);
		if (!response) return false;   // pool exhausted: drop, peer retransmits (#101A)
		response->setHeader("SIP/2.0 481 Call/Transaction Does Not Exist");
		response->clearBody();
		response->setVia(sipwire::viaWithReceived(data->getVia(), data->getSource()));
		_outbox.emplace_back(data->getSource(), std::move(response));
		return false;
	}

	auto ok = getMessageFromPool(*data);
	if (!ok) return true;   // pool exhausted: drop, peer retransmits (#101A) -- bridge was found, so this counts as handled
	ok->setHeader(SipMessageTypes::OK);
	ok->setVia(sipwire::viaWithReceived(data->getVia(), data->getSource()));
	// To: is left exactly as `data` carried it -- this is an in-dialog request,
	// so the phone already echoed the tag it learned from the ORIGINAL 200 OK.
	// buildOkWithSdp() mints a fresh tag for a first answer; calling it here
	// would append a second tag onto the one already present.
	addCapabilityHeaders(*ok);
	const std::string sdpBody = buildMediaSdp(_localIp, bridge->receiverPort(),
		/*sendrecv=*/true, data->getTelephoneEventPayloadType());
	ok->clearBody();
	{
		std::string raw = ok->toString();
		size_t sep = raw.find("\r\n\r\n");
		if (sep != std::string::npos)
		{
			std::string_view headerView(raw.data(), sep);
			if (headerView.find("application/sdp") == std::string_view::npos)
			{
				raw.insert(sep, "\r\nContent-Type: application/sdp");
				sep = raw.find("\r\n\r\n");
			}
			raw.erase(sep + 4);
			raw += sdpBody;
		}
		ok->reset(std::move(raw), data->getSource());
	}
	ok->syncContentLength();
	_outbox.emplace_back(data->getSource(), std::move(ok));

	// Issue #263: sdp::isHold() is model-aware and section-explicit, and
	// catches the legacy RFC 2543 c=0.0.0.0 hold signal getSdpDirection()
	// never looked for at all. recvonly is kept as an explicit hold signal
	// here too -- RFC 3264 s8.4 does not call recvonly hold and isHold()
	// correctly does not treat it as one, but this PBX always has at all
	// three hold/resume sites, and the swap must not silently drop that
	// rather than deciding it.
	SipSdpMessage* sdpMsg = data->hasSdp() ? static_cast<SipSdpMessage*>(data.get()) : nullptr;
	const auto dir = data->getSdpDirection();
	const bool holding = (sdpMsg && sdpMsg->isHoldOffer()) ||
		dir == SipMessage::SdpDirection::RecvOnly;
	bridge->setHeld(holding);

	if (session->getSessionExpiresSeconds() > 0)
	{
		session->armSessionTimer(session->getSessionExpiresSeconds(),
		                         session->isRefresher(),
		                         std::chrono::steady_clock::now());
	}
	session->setState(holding ? Session::State::Held : Session::State::Connected);
	queueLog(std::string(holding ? "Hold (anchor): " : "Resume (anchor): ") +
		std::string(src->getNumber()) + " call " + callIdStr, false);
	return true;
}

// ── Mid-dialog re-INVITE (RFC 3261 §12.2 hold/resume) ────────────────────────

void RequestsHandler::onReinvite(std::shared_ptr<SipMessage> data)
{
	auto sessionOpt = getSession(data->getCallID());
	if (!sessionOpt.has_value())
	{
		return;
	}
	auto session = sessionOpt.value();
	auto src = session->getSrc();
	auto dest = session->getDest();

	const std::string destNum = dest ? dest->getNumber() : "";

	// Issue #218: the anchored leg is answered, not refused -- see
	// answerAnchorReinvite()'s doc comment. Checked before the virtual-leg
	// refusal below, which still applies to 777/888 (no real peer at all).
	if (destNum == kAnchorCallExt && src && dest)
	{
		answerAnchorReinvite(data, session, src);
		return;
	}

	// Virtual-extension legs (777 echo, 888 conference) have no real peer to
	// relay the offer to — their "dest" is a stand-in SipClient carrying the
	// CALLER's own address, so relaying would send the phone its own
	// re-INVITE back. Decline instead, so the holding phone keeps the call on
	// the original SDP.
	if (destNum == "777" || destNum == ConferenceRoom::EXT || (session && session->isTrunk()) || !src || !dest)
	{
		auto response = getMessageFromPool(*data);
		if (!response) return;   // pool exhausted: drop, peer retransmits (#101A)
		response->setHeader("SIP/2.0 488 Not Acceptable Here");
		response->clearBody();
		std::string activeIp = _localIp;
		response->setVia(sipwire::viaWithReceived(data->getVia(), data->getSource()));
		_outbox.emplace_back(data->getSource(), std::move(response));
		return;
	}

	// Identify the sending leg by source address; the relay target is the peer.
	std::shared_ptr<SipClient> peer;
	if (sameAddress(data->getSource(), src->getAddress()))
	{
		peer = dest;
	}
	else if (sameAddress(data->getSource(), dest->getAddress()))
	{
		peer = src;
	}
	if (!peer)
	{
		return; // not from either leg of this dialog: ignore
	}

	// Relay UNTOUCHED — no clearBody()/enforceG711() — so the hold SDP
	// (a=sendonly/inactive) and its Content-Length reach the peer intact.
	_outbox.emplace_back(peer->getAddress(), data);

	// A re-INVITE from either leg is evidence the endpoint is alive — it counts
	// as a session-timer refresh.
	if (session->getSessionExpiresSeconds() > 0)
	{
		session->armSessionTimer(session->getSessionExpiresSeconds(),
		                         session->isRefresher(),
		                         std::chrono::steady_clock::now());
	}

	// Track hold state from the offered SDP. Issue #263: sdp::isHold() (model-
	// aware, section-explicit -- see answerAnchorReinvite()'s identical swap
	// for the full reasoning) replaces the direction-only getSdpDirection()
	// scan, adding the legacy RFC 2543 c=0.0.0.0 signal; recvonly is kept as
	// an explicit hold signal alongside it, same as before this change. RFC
	// 3264: an absent direction attribute AND a real connection address
	// implies sendrecv (an active call).
	SipSdpMessage* sdpMsg = data->hasSdp() ? static_cast<SipSdpMessage*>(data.get()) : nullptr;
	const auto dir = data->getSdpDirection();
	if ((sdpMsg && sdpMsg->isHoldOffer()) || dir == SipMessage::SdpDirection::RecvOnly)
	{
		session->setState(Session::State::Held);
		queueLog("Hold: " + std::string(data->getFromNumber()) + " held call " + std::string(data->getCallID()));
	}
	else
	{
		session->setState(Session::State::Connected);
		queueLog("Hold: call " + std::string(data->getCallID()) + " resumed");
	}
}

// ── Mid-dialog UPDATE (RFC 3311 hold/resume / session-timer keep-alive) ──────

void RequestsHandler::onUpdate(std::shared_ptr<SipMessage> data)
{
	auto sessionOpt = getSession(data->getCallID());
	if (!sessionOpt.has_value())
	{
		auto resp = getMessageFromPool(*data);
		if (!resp) return;   // pool exhausted: drop, peer retransmits (#101A)
		resp->setHeader("SIP/2.0 481 Call/Transaction Does Not Exist");
		resp->clearBody();
		_outbox.emplace_back(data->getSource(), std::move(resp));
		return;
	}
	auto session = sessionOpt.value();
	std::string activeIp = _localIp;

	if (!data->hasSdp())
	{
		// Bodiless UPDATE: session-timer refresh — 200 OK and reset expiry.
		auto resp = getMessageFromPool(*data);
		if (!resp) return;   // pool exhausted: drop, peer retransmits (#101A)
		resp->setHeader(SipMessageTypes::OK);
		resp->setVia(sipwire::viaWithReceived(data->getVia(), data->getSource()));
		resp->clearBody();
		resp->syncContentLength();
		_outbox.emplace_back(data->getSource(), std::move(resp));

		if (session->getSessionExpiresSeconds() > 0)
		{
			session->armSessionTimer(session->getSessionExpiresSeconds(),
			                         session->isRefresher(),
			                         std::chrono::steady_clock::now());
		}
		return;
	}

	// SDP-bearing UPDATE: relay to the peer leg (same logic as onReinvite).
	auto src  = session->getSrc();
	auto dest = session->getDest();
	const std::string destNum = dest ? dest->getNumber() : "";

	// Issue #218: same anchored-leg answer as onReinvite() — see
	// answerAnchorReinvite()'s doc comment.
	if (destNum == kAnchorCallExt && src && dest)
	{
		answerAnchorReinvite(data, session, src);
		return;
	}

	// Same virtual-leg guard as onReinvite() above: 777/888 have no peer leg.
	if (destNum == "777" || destNum == ConferenceRoom::EXT || (session && session->isTrunk()) || !src || !dest)
	{
		auto resp = getMessageFromPool(*data);
		if (!resp) return;   // pool exhausted: drop, peer retransmits (#101A)
		resp->setHeader("SIP/2.0 488 Not Acceptable Here");
		resp->clearBody();
		_outbox.emplace_back(data->getSource(), std::move(resp));
		return;
	}

	std::shared_ptr<SipClient> peer;
	if (sameAddress(data->getSource(), src->getAddress()))
		peer = dest;
	else if (sameAddress(data->getSource(), dest->getAddress()))
		peer = src;

	if (!peer) return;

	_outbox.emplace_back(peer->getAddress(), data);

	if (session->getSessionExpiresSeconds() > 0)
	{
		session->armSessionTimer(session->getSessionExpiresSeconds(),
		                         session->isRefresher(),
		                         std::chrono::steady_clock::now());
	}

	// Issue #263: same isHoldOffer()+recvonly swap as onReinvite() above. The
	// cast is unguarded here (unlike the other two sites) because the
	// `!data->hasSdp()` branch above already returned for a bodiless UPDATE --
	// every message reaching this point has SDP.
	SipSdpMessage* sdpMsg = static_cast<SipSdpMessage*>(data.get());
	const auto dir = data->getSdpDirection();
	if (sdpMsg->isHoldOffer() || dir == SipMessage::SdpDirection::RecvOnly)
	{
		session->setState(Session::State::Held);
		queueLog("Update/Hold: " + std::string(data->getFromNumber()) +
		         " held call " + std::string(data->getCallID()));
	}
	else
	{
		session->setState(Session::State::Connected);
		queueLog("Update/Resume: call " + std::string(data->getCallID()) + " resumed");
	}
}

// ── BYE source authorization ──────────────────────────────────────────────────

bool RequestsHandler::isDialogSourceAuthorized(const std::shared_ptr<Session>& session,
	const sockaddr_in& source) const
{
	if (!session)
	{
		// Out-of-dialog BYE on a non-existent Call-ID: harmless — nothing to tear down.
		return true;
	}

	auto src  = session->getSrc();
	auto dest = session->getDest();

	// Fail-open for any dialog with a missing leg (half-set-up session).
	if (!src || !dest)
	{
		return true;
	}

	// Compare source IP only (port-agnostic): a phone may send the BYE from the same
	// contact IP but a different ephemeral UDP port than the original INVITE.
	const uint32_t fromIp = source.sin_addr.s_addr;
	return fromIp == src->getAddress().sin_addr.s_addr ||
	       fromIp == dest->getAddress().sin_addr.s_addr;
}

// ── BLF presence: FSM lives in BlfSubscriptions.cpp ──────────────────────────

void RequestsHandler::onSubscribe(std::shared_ptr<SipMessage> data)
{
	_blf.onSubscribe(data);
}

// ── RFC 4028 session timers ───────────────────────────────────────────────────

void RequestsHandler::armSessionTimer(Session* session,
                                       const std::shared_ptr<SipMessage>& ok200)
{
	uint32_t secs = ok200->getSessionExpiresSecs();
	if (secs == 0) return;

	// Capture the dialog From/To FIRST, before any decision about the reaper.
	// sweepSessionTimers() and the #72 guard at the bottom of this file both read
	// getDialogFrom()/getDialogTo(), and attended transfer reads them to address
	// its cross re-INVITEs — none of that is conditional on a timer being armed,
	// so hoisting this above the early return below keeps it unconditional.
	session->setDialogHeaders(std::string(ok200->getFrom()), std::string(ok200->getTo()));

	// ── Who is the refresher? (RFC 4028 §7.4) ────────────────────────────────
	// The refresher parameter on a 2xx names ONE OF THE TWO UAs of the session:
	// "uas" is the party that ANSWERED the INVITE (the callee, whose 200 OK this
	// is), "uac" is the party that SENT it. It never names an intermediary.
	//
	// The orientation at this call site is not the obvious one, so spell it out.
	// This PBX does not re-originate calls on the ordinary call path: onInvite()
	// clones the CALLER's INVITE, rewrites only Contact, and forwards it
	// (RequestsHandler.cpp:1578-1581); CallForker::forkInvite does the same for a
	// ring group (CallForker.cpp:22-50). From/To/Call-ID/CSeq stay the caller's
	// end to end, and this handler is only ever reached from onOk()'s generic
	// relay branch (:3408) — every path where the server really is the UAC
	// (register beep, park, attended-transfer splice, inbound anchor) is
	// intercepted earlier in onOk() at :3197/:3205/:3213/:3226 and never gets
	// here. So on this leg the UAC is the CALLER'S PHONE and the UAS is the
	// CALLEE'S PHONE. The PBX is neither, and therefore is never the refresher.
	//
	// The old `weRefresh = (ref == "uas")` asserted the PBX was the refresher in
	// exactly the case where the header designates the CALLEE — the opposite of
	// what it reads — and it is the wrong question besides. It was inert only
	// because _isRefresher has no consumer that generates anything: nothing in
	// this firmware has ever sent a refreshing re-INVITE or UPDATE
	// (Session::getNextRefresh() has zero call sites).
	const auto ref = ok200->getSessionExpiresRefresher();
	const bool calleeRefreshes = (ref == "uas");
	const bool callerRefreshes = (ref == "uac");
	constexpr bool kPbxIsRefresher = false;   // derivation above

	// ── Only arm a reaper we can actually expect to be fed ───────────────────
	// RFC 4028's UAS rules require a 2xx that carries Session-Expires to carry a
	// refresher parameter too (section number deliberately omitted — §7.4 is
	// cited above only for what the parameter MEANS, which is the part this
	// change turns on). When the parameter is absent, nobody has been made
	// responsible for refreshing, so no refresh is owed and the only thing this
	// timer can ever do is BYE a healthy call.
	//
	// That is not hypothetical: this PBX builds most responses by cloning the
	// REQUEST (getMessageFromPool(*data) + setHeader), so its own 200 OK echoes
	// the caller's Session-Expires back with no refresher added — see the real
	// pjsip capture in tests/interop/.logs/pjsua-A.log (the PBX's 200 OK on the
	// 777 leg comes back carrying pjsua's own Session-Expires/Min-SE, and pjsua
	// then has to pick a refresher itself). A callee that answers the same way
	// lands the same header here.
	//
	// Declining to arm is the safe direction: the worst case is that a dead
	// dialog lingers until the ordinary BYE/CANCEL or the no-answer and orphan
	// sweeps in tick() clear it, whereas arming wrongly hangs up a live call.
	if (!calleeRefreshes && !callerRefreshes)
	{
		queueLog("[session timer] Session-Expires with no refresher parameter "
		         "(RFC 4028 §7.4) — reaper not armed for " +
		         std::string(ok200->getCallID()));
		return;
	}

	session->armSessionTimer(secs, kPbxIsRefresher, std::chrono::steady_clock::now());
}

void RequestsHandler::sweepSessionTimers(std::chrono::steady_clock::time_point now)
{
	std::vector<std::string> toExpire;
	for (const auto& [callID, session] : _sessions)
	{
		if (session->getSessionExpiresSeconds() == 0) continue;
		const auto st = session->getState();
		if (st != Session::State::Connected && st != Session::State::Held) continue;

		// Never reap a session whose refresh we would REFUSE. This guard mirrors
		// the virtual/missing-peer early return in onReinvite() (:5485) and
		// onUpdate() (:5585) deliberately: those answer 488 Not Acceptable Here
		// and return ABOVE their re-arm (:5520 / :5607), so for any dialog in that
		// set a refresh arrives, is refused, and never touches the expiry clock —
		// after which the sweep below BYEs a call that is perfectly healthy. The
		// set we refuse to refresh and the set we refuse to reap must stay
		// identical or that asymmetry comes straight back.
		//
		// arming alone cannot prevent this. armSessionTimer() only runs from
		// onOk()'s relay branch (:3408), where dest was just resolved to a
		// REGISTERED client — so every armed session starts serviceable and can
		// only become unserviceable later. The verified way that happens today is
		// the DTMF feature codes: *69 (DtmfFeatureCodes.cpp:263) and *11 (:286)
		// take the caller's LIVE session and setDest() a per-session dummy peer
		// numbered "777" to reroute its RTP to the echo loopback. From that digit
		// on, the dialog is in onReinvite's 488 set while still being a real,
		// connected two-party call with an armed reaper — issue #198's spurious
		// hang-up, reachable with no anchor, no trunk and no transfer.
		//
		// The `!src || !dest` half is defensive: no current path unsets a leg on a
		// Connected session (the attended-transfer splice deliberately leaves both
		// in place — see Session::wasTransferorSrc()'s comment — and park builds a
		// FRESH session rather than mutating the connected one, ParkOrbit.cpp:66-69).
		// Nothing here is leaked: ordinary BYE handling, the anchor ACK/no-answer
		// reaper and the park sweep in tick() already own these teardowns.
		auto sweepSrc  = session->getSrc();
		auto sweepDest = session->getDest();
		const std::string sweepDestNum = sweepDest ? sweepDest->getNumber() : "";
		// Issue #164: a trunk leg is in this set too, and by flag rather than
		// by dest number -- its dummy dest is a marker, not a dialable code.
		// The comment above is the binding constraint: the set we refuse to
		// REFRESH and the set we refuse to REAP must stay identical, so this
		// matches the isTrunk() guard added to onReinvite()/onUpdate(). A relay
		// leg has no local UA to answer a refresh, so without this the sweep
		// BYEs a perfectly healthy PSTN call partway through.
		if (!sweepSrc || !sweepDest || session->isTrunk() ||
			sweepDestNum == "777" || sweepDestNum == ConferenceRoom::EXT ||
			sweepDestNum == kAnchorCallExt)
		{
			continue;
		}

		if (now >= session->getSessionExpiry())
		{
			toExpire.push_back(callID);
		}
	}

	for (const auto& callID : toExpire)
	{
		auto it = _sessions.find(callID);
		if (it == _sessions.end()) continue;
		auto session = it->second;
		auto src  = session->getSrc();
		auto dest = session->getDest();
		const std::string& dFrom = session->getDialogFrom();
		const std::string& dTo   = session->getDialogTo();

		// Guard on both dialog headers: a BYE with an empty From or To is malformed
		// and phones will drop it, leaving the session alive and re-firing every sweep
		// tick. dTo can be empty if armSessionTimer was invoked before the 200 OK set
		// dialog headers (e.g. a partial onReinvite path). (#72)
		if (src && !dFrom.empty() && !dTo.empty())
		{
			auto b = buildServerBye(src->getNumber(), src->getAddress(), callID, dTo, dFrom);
			if (b) _outbox.emplace_back(src->getAddress(), std::move(b));
		}
		if (dest && !dFrom.empty() && !dTo.empty())
		{
			auto b = buildServerBye(dest->getNumber(), dest->getAddress(), callID, dFrom, dTo);
			if (b) _outbox.emplace_back(dest->getAddress(), std::move(b));
		}
		queueLog("[session timer] expired — BYE sent for " + callID, true);
		endCall(callID,
		        src  ? src->getNumber()  : "",
		        dest ? dest->getNumber() : "",
		        "session timer expired");
	}
}

// ── Paging zones (980–989) ────────────────────────────────────────────────────
// findPageZone/isPageZoneDialog now live on _cfg (PbxFeatureConfig).

// ── Directed / group call pickup (Issue #68) ──────────────────────────────────
// See PbxConfig.hpp's isGroupPickupCode/directedPickupTarget doc comment: pickup
// groups are ring-group membership, reused as-is.

bool RequestsHandler::isSessionRingingExt(const std::shared_ptr<Session>& session, const std::string& ext) const
{
	if (!session || session->getState() != Session::State::Invited)
	{
		return false;
	}
	if (session->isBroadcast())
	{
		// Ring-all / hunt: the currently-ringing member(s) live in
		// pendingTargets (hunt keeps exactly one entry there at a time).
		for (const auto& t : session->getPendingTargets())
		{
			if (t && t->getNumber() == ext) return true;
		}
		return false;
	}
	// Direct (proxied 1:1) call: the callee extension is the stored original
	// INVITE's own To user-part — always retained now (see onInvite's direct-
	// call branch), not only when a conditional forward is configured.
	auto inv = session->getInviteMessage();
	return inv && inv->getToNumber() == ext;
}

std::shared_ptr<Session> RequestsHandler::findRingingSessionAmong(const std::vector<std::string>& candidates,
	std::string& outCallId, std::string& outExt) const
{
	std::shared_ptr<Session> best;
	std::chrono::steady_clock::time_point bestStart;
	for (const auto& [callId, session] : _sessions)
	{
		if (!session) continue;
		for (const auto& ext : candidates)
		{
			if (!isSessionRingingExt(session, ext)) continue;
			if (!best || session->getStartTime() < bestStart)
			{
				best = session;
				bestStart = session->getStartTime();
				outCallId = callId;
				outExt = ext;
			}
			break;   // this session matched; no need to try its other candidates
		}
	}
	return best;
}

void RequestsHandler::setPageZone(const std::string& zoneExt, const std::string& members)
{
	std::vector<std::pair<bool, std::string>> localLogs;
	{
		std::lock_guard<std::mutex> lock(_mutex);
		_cfg.setPageZone(zoneExt, members);
		localLogs = std::move(_logQueue);
		_logQueue.clear();
	}

	for (const auto& log : localLogs)
	{
		if (log.first) std::cerr << log.second << '\n';
		else std::cout << log.second << '\n';
	}
}

std::vector<std::pair<std::string, std::string>> RequestsHandler::getPageZones()
{
	std::lock_guard<std::mutex> lock(_snapshotMutex);
	return _snapshot.pageZones;
}

// ── Call parking (orbits 700–709): FSM lives in ParkOrbit.cpp ────────────────

std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>> RequestsHandler::drainOutbox()
{
	// Stage B of the TelephonyAnchorClient port: merge in anything the CallEvent
	// callback (or an async worker's completion) queued to _asyncOutbox — it runs
	// off the SIP receive thread, after handle()/tick() already cleared _outbox
	// for this pass, so it cannot append there directly. Merged in BEFORE the
	// retransmit-tracking scan below so a forked inbound INVITE
	// (buildInboundInviteFork) gets the same Timer A/B coverage as any other.
	for (auto& e : _asyncOutbox)
	{
		_outbox.push_back(std::move(e));
	}
	_asyncOutbox.clear();

	// The single exit every deferred message passes through. RFC 3261 §17:
	// register outgoing messages for retransmit here, so Timer A/B, E/F
	// (requests) and G/H/J (our own responses) coverage is structural rather
	// than something each flush site re-implements — a new flush path would
	// otherwise send one-shot UDP messages that are simply lost on a dropped
	// packet. classify() (TransactionLayer.cpp) tracks INVITE requests, every
	// other request except ACK/OPTIONS/REGISTER (NOTIFY included), and our
	// own responses to INVITE/BYE/CANCEL/REFER/UPDATE; everything else is
	// left untracked.
	//
	// Ordering matters (#70): the scan must run after everything that appends to
	// _outbox during this pass (BLF NOTIFYs, tick()-originated forks — park
	// ring-back, hunt-group next-ring, CFNA redirect — and now the async-anchor
	// merge above), which is exactly why it belongs at the drain rather than at
	// any individual enqueue.
	for (const auto& [addr, msg] : _outbox)
	{
		// Skip the one thing that is not ours to retransmit: the inbound message
		// itself, forwarded verbatim by a relay handler. See _passThroughMsg.
		if (msg.get() != _passThroughMsg)
		{
			_txLayer.maybeTrack(addr, msg);
		}
		// Issue #33: /api/pcap capture, outbound side. Same single choke point as
		// the retransmit registration above — every deferred message leaves
		// through here regardless of which call site (handle(), tick(),
		// sendMessageTo()) queued it.
		msg->toString(_pcapCapture.recordInto(/*outbound=*/true, addr));
	}

	auto drained = std::move(_outbox);
	_outbox.clear();
	return drained;
}

void RequestsHandler::refreshParkSnapshot()
{
	auto rows = _park.snapshotRows(std::chrono::steady_clock::now(), /*onlyParked=*/false);
	std::lock_guard<std::mutex> snapLock(_snapshotMutex);
	_snapshot.parkedCalls = std::move(rows);
}

std::vector<std::tuple<std::string, std::string, std::string, int>> RequestsHandler::getParkedCalls()
{
	std::lock_guard<std::mutex> lock(_snapshotMutex);
	return _snapshot.parkedCalls;
}

// ── Build helpers ─────────────────────────────────────────────────────────────

std::shared_ptr<SipMessage> RequestsHandler::buildOkWithSdp(
	const std::shared_ptr<SipMessage>& inviteMsg,
	const std::string& /*activeIp*/,   // Via now carries the request's real source
	const std::string& toTag,
	const std::string& sdpBody)
{
	auto ok = getMessageFromPool(*inviteMsg);
	if (!ok) return nullptr;   // pool exhausted: propagate, caller drops (#101A)
	ok->setHeader(SipMessageTypes::OK);
	ok->setVia(sipwire::viaWithReceived(inviteMsg->getVia(), inviteMsg->getSource()));
	ok->setTo(std::string(inviteMsg->getTo()) + ";tag=" + toTag);
	ok->setContact(buildContact(inviteMsg->getToNumber()));
	// Every caller of this builder answers an INVITE the PBX itself terminates —
	// the 888 conference leg, the 555/anchor bridge and the inbound-anchor
	// handset leg — so the PBX is the real UAS on the dialog this 2xx opens and
	// these headers describe it, not a phone being spoken for. RFC 3261 §13.3.1
	// / §20.5: a 2xx to an INVITE SHOULD carry Allow, which is also the only
	// place a phone looks to decide whether it may send UPDATE in this dialog
	// (RFC 3311 §5.1). Added BEFORE the body work below so the header block is
	// final when Content-Type/Content-Length are recomputed off the raw string.
	addCapabilityHeaders(*ok);
	ok->clearBody();
	{
		std::string raw = ok->toString();
		size_t sep = raw.find("\r\n\r\n");
		if (sep != std::string::npos)
		{
			std::string_view headerView(raw.data(), sep);
			if (headerView.find("application/sdp") == std::string_view::npos)
			{
				raw.insert(sep, "\r\nContent-Type: application/sdp");
				sep = raw.find("\r\n\r\n");
			}
			raw.erase(sep + 4);
			raw += sdpBody;
		}
		ok->reset(std::move(raw), inviteMsg->getSource());
	}
	// See the note in the 440 media path: sdpBody is already the server's own
	// PCMU-only offer; enforceG711() would widen it to an invalid "0 8 101".
	ok->syncContentLength();
	return ok;
}

std::shared_ptr<SipMessage> RequestsHandler::buildServerBye(
	const std::string& destExt,
	const sockaddr_in& destAddr,
	const std::string& callId,
	const std::string& fromHeader,
	const std::string& toHeader,
	uint32_t cseq)
{
	std::string activeIp = _localIp;
	std::string srcIpPort = activeIp + ":" + std::to_string(_serverPort);
	std::string destIpPort = sipwire::addrToIpPort(destAddr);
	std::string branch = "z9hG4bK" + IDGen::GenerateID(12);

	std::ostringstream ss;
	ss << "BYE sip:" << destExt << "@" << destIpPort << " SIP/2.0\r\n"
	   << "Via: SIP/2.0/UDP " << srcIpPort << ";branch=" << branch << "\r\n"
	   << "From: " << stripHeaderName(fromHeader) << "\r\n"
	   << "To: " << stripHeaderName(toHeader) << "\r\n"
	   << "Call-ID: " << stripHeaderName(callId) << "\r\n"
	   << "CSeq: " << cseq << " BYE\r\n"
	   << "Max-Forwards: 70\r\n"
	   << "Content-Length: 0\r\n\r\n";

	return getMessageFromPool(ss.str(), destAddr);
}

std::shared_ptr<SipClient> RequestsHandler::allocateVirtualPeer(std::string number, sockaddr_in address, int expiresSeconds)
{
	// A virtual peer is owned solely by the Session._dest it backs, so a pool slot is
	// free precisely when only the pool itself still references it (use_count()==1).
	for (auto& peer : _virtualPeerPool)
	{
		if (peer.use_count() == 1)
		{
			peer->reset(std::move(number), address, expiresSeconds);
			return peer;
		}
	}
	// Pool drained: fall back to the heap, bounded the same way the message pool
	// is (Issue #101(A)). Past the ceiling this returns nullptr and the caller
	// abandons the park/BLF operation rather than allocating without limit.
	//
	// No pool lock here, unlike SipMessagePool's acquirePooledMessage(): _virtualPeerPool is a
	// per-instance member and every caller — the internal sites and ParkOrbit via
	// PbxEnv::allocVirtualPeer — already runs under _mutex. The counter is still
	// atomic because its decrement happens in the deleter, which runs wherever
	// the owning Session finally releases it.
	static std::atomic<std::size_t> vpeerWarnCount{0};
	if (s_vpeerHeapFallbacksInFlight.load(std::memory_order_relaxed) >= POCKETDIAL_VPEER_HEAP_FALLBACK_MAX)
	{
		sipmsgpool::logPoolExhausted("Virtual-peer", sipmsgpool::PoolPressure::Refused, vpeerWarnCount);
		return nullptr;
	}
	sipmsgpool::logPoolExhausted("Virtual-peer", sipmsgpool::PoolPressure::Fallback, vpeerWarnCount);

	SipClient* raw = nullptr;
	try
	{
		raw = new SipClient(std::move(number), address, expiresSeconds);
	}
	catch (const std::bad_alloc&)
	{
		return nullptr;   // budget untouched
	}
	s_vpeerHeapFallbacksInFlight.fetch_add(1, std::memory_order_relaxed);
	try
	{
		return std::shared_ptr<SipClient>(raw, VpeerFallbackDeleter{});
	}
	catch (const std::bad_alloc&)
	{
		// Constructor already ran the deleter on `raw` — freed and decremented.
		return nullptr;
	}
}

// ─────────────────────────────────────────────────────────────────────────────
//  Generic ITSP SIP trunk: the B2BUA wiring (Issue #164)
// ─────────────────────────────────────────────────────────────────────────────
//
// SipTrunk owns the carrier-facing dialog and TrunkResolver owns the SBC's
// address. What lives here is everything that joins them to a handset: picking
// a relay pair, cross-wiring it, and translating between the two dialogs'
// lifecycles in both directions.
//
// The relay is two RtpReceivers and no RtpSender. A trunk must put the
// carrier's packets back on the wire byte for byte -- RFC 4733 telephone-event
// has no representation in RtpSender's PCMU FrameProvider, so a digit crossing
// it would arrive as noise. RtpReceiver::sendRaw() re-emits the original
// packet from the receiver's own socket, which also makes the media symmetric
// with the port the SDP advertised.

namespace
{
	// Identity for the per-session dummy dest a trunk call carries. Non-numeric
	// on purpose: every other virtual leg borrows a DIALABLE code (777, 888,
	// 555) because you reach it by dialling it, but a trunk is reached through
	// a dial-plan rule and has no code of its own. A non-numeric marker cannot
	// collide with an extension, a park orbit, a page zone or a PSTN number, so
	// it needs no entry in the reserved-identity guards -- unlike the voicemail
	// leg's "700", which sits inside the park-orbit range.
	constexpr const char* kTrunkCallExt = "trunk";

	// RtpReceiver::RawSink is a plain function pointer plus a ctx (issue #284:
	// std::function's small-object buffer is 8 bytes on this toolchain, so a
	// capturing lambda would heap-allocate on a media path). The ctx is the
	// PEER receiver, and relaying is one call.
	void trunkRelayForward(void* ctx, const RtpReceiver::RtpPacket& pkt)
	{
		if (!ctx) return;
		static_cast<RtpReceiver*>(ctx)->sendRaw(pkt);
	}
}

void RequestsHandler::setTrunkConfig(const SipTrunk::Config& cfg)
{
	std::lock_guard<std::mutex> lock(_mutex);
	_sipTrunk.setConfig(cfg);
	// The operator has pointed the trunk somewhere else, so any cached address
	// is not merely stale, it is wrong -- see TrunkResolver::clear().
	_trunkResolver.clear();
}

SipTrunk::Config RequestsHandler::getTrunkConfig()
{
	std::lock_guard<std::mutex> lock(_mutex);
	// Safe to return by value: the digest password is deliberately NOT a member
	// of Config (it lives in SipTrunk's own buffer), so this cannot leak it.
	return _sipTrunk.config();
}

bool RequestsHandler::setTrunkCredentials(std::string_view password)
{
	std::lock_guard<std::mutex> lock(_mutex);
	return _sipTrunk.setCredentials(password);
}

void RequestsHandler::applyStoredTrunkConfig()
{
	// The ONE place the persisted form is translated into engine state. Boot
	// and the HTTP PUT both come through here so the two cannot drift -- a PUT
	// that persisted without applying would leave the running trunk pointed at
	// the old carrier until the next reboot, which is the kind of bug that only
	// shows up during a cutover.
	const TrunkConfigStore::Config stored = TrunkConfigStore::load();

	SipTrunk::Config cfg;
	auto copyField = [](char* dst, size_t cap, const std::string& src)
	{
		const size_t n = src.size() < cap - 1 ? src.size() : cap - 1;
		std::memcpy(dst, src.data(), n);
		dst[n] = '\0';
	};
	copyField(cfg.host,      sizeof(cfg.host),      stored.host);
	copyField(cfg.proxyHost, sizeof(cfg.proxyHost), stored.proxyHost);
	copyField(cfg.fromUser,  sizeof(cfg.fromUser),  stored.fromUser);
	copyField(cfg.callerId,  sizeof(cfg.callerId),  stored.callerId);
	// Empty authUser means "use fromUser", matching SipRegistrationClient's
	// "digest username (often == aorUser)". Resolving the default HERE rather
	// than at the challenge site means what the operator sees in the UI and
	// what would go on the wire are the same string.
	copyField(cfg.authUser,  sizeof(cfg.authUser),
		stored.authUser.empty() ? stored.fromUser : stored.authUser);
	cfg.port      = stored.port;
	cfg.proxyPort = stored.proxyPort;
	cfg.enabled   = stored.enabled;

	// ONE critical section for the config AND the credential. Two separate
	// acquisitions would leave a window in which the SIP thread can route a
	// call with the new carrier and the old password. That is harmless only
	// while nothing transmits the password; the day 401/407 lands, a cutover
	// save would sign INVITEs to carrier B with carrier A's credential. Fix
	// the window now rather than leave a note for someone to miss.
	//
	// Note for future callers: this takes _mutex itself, so it must NOT be
	// called with _mutex already held -- the mutex is non-recursive.
	std::lock_guard<std::mutex> lock(_mutex);
	_sipTrunk.setConfig(cfg);
	// The operator has pointed the trunk somewhere else, so any cached address
	// is not merely stale, it is wrong -- see TrunkResolver::clear().
	_trunkResolver.clear();

	// Checked, not discarded. The HTTP route caps the password well below
	// kMaxSecret, but this path reads raw NVS, which an older or different
	// build could have written. On rejection setCredentials() leaves the
	// previous secret in place, so engine and store would silently diverge --
	// which is invisible from the UI, because hasPassword is reported from the
	// STORE, not from the engine.
	if (!_sipTrunk.setCredentials(stored.pass))
	{
		_sipTrunk.clearCredentials();
		queueLog("trunk: stored password rejected (too long for this build); "
		         "credential cleared -- re-enter it on /setup/trunk", true);
	}
}

#if !defined(ESP_PLATFORM) && !defined(ESP32) && !defined(ARDUINO)
size_t RequestsHandler::trunkRelaysInUseForTest()
{
	std::lock_guard<std::mutex> lock(_mutex);
	size_t n = 0;
	for (int i = 0; i < static_cast<int>(POCKETDIAL_MAX_TRUNK_CALLS); ++i)
	{
		if (_trunkRx[i].isActive() || _handsetRx[i].isActive()) ++n;
	}
	return n;
}

void RequestsHandler::expireTrunkDeadlinesForTest()
{
	std::lock_guard<std::mutex> lock(_mutex);
	_sipTrunk.expireDeadlinesForTest();
}

TrunkResolver::Status RequestsHandler::trunkResolveStatusForTest()
{
	std::lock_guard<std::mutex> lock(_mutex);
	sockaddr_in out{};
	return _trunkResolver.lookup(_sipTrunk.config().transportHost(),
		_sipTrunk.config().transportPort(), out, std::chrono::steady_clock::now());
}
#endif

int RequestsHandler::findFreeTrunkRelay() const
{
	for (int i = 0; i < static_cast<int>(POCKETDIAL_MAX_TRUNK_CALLS); ++i)
	{
		if (!_trunkRx[i].isActive() && !_handsetRx[i].isActive()) return i;
	}
	return -1;
}

void RequestsHandler::releaseTrunkRelay(int slot)
{
	if (slot < 0 || slot >= static_cast<int>(POCKETDIAL_MAX_TRUNK_CALLS)) return;

	// Drop the cross-wiring before stopping, so a packet in flight on the other
	// receiver's task cannot be handed to a receiver that is mid-stop. Clearing
	// the sink is a lock-protected store inside RtpReceiver; stop() then joins.
	_trunkRx[slot].setRawSink(nullptr, nullptr);
	_handsetRx[slot].setRawSink(nullptr, nullptr);
	_trunkRx[slot].stop();
	_handsetRx[slot].stop();
}

void RequestsHandler::refuseRingingTrunk(const std::string& callId, int carrierStatus)
{
	// Same contract as refuseRingingAnchor(): endCall() never sends a final
	// response, so any path that gives up while the handset is still ringing
	// must answer it here first or the phone rings forever.
	auto sit = _sessions.find(callId);
	if (sit == _sessions.end() || !sit->second) return;
	if (sit->second->getState() != Session::State::Invited) return;
	auto invite = sit->second->getInviteMessage();
	if (!invite) return;
	auto resp = getMessageFromPool(*invite);
	if (!resp) return;

	// Map the carrier's status onto one that means the same thing to a handset.
	// Passing the carrier's own code straight through is wrong for the codes
	// that describe the CARRIER's state rather than the callee's: a 503 from
	// the SBC means "this trunk is unavailable", which a phone should hear as
	// the call not completing, not as the called party being unavailable.
	const char* line = "SIP/2.0 502 Bad Gateway";
	switch (carrierStatus)
	{
		case 486: line = "SIP/2.0 486 Busy Here";          break;  // callee busy: true end to end
		case 404: line = "SIP/2.0 404 Not Found";          break;  // bad number: true end to end
		case 480:
		case 408:
		case 503: line = "SIP/2.0 503 Service Unavailable"; break; // carrier-side, incl. our timeout
		default:  break;                                           // anything else: 502
	}
	resp->setHeader(line);
	resp->clearBody();
	resp->setVia(sipwire::viaWithReceived(invite->getVia(), invite->getSource()));
	resp->setContact(buildContact(std::string(invite->getToNumber())));
	_outbox.emplace_back(invite->getSource(), std::move(resp));
}

bool RequestsHandler::routeTrunkCall(const std::shared_ptr<SipMessage>& data,
	const std::shared_ptr<SipClient>& caller, const std::string& destination)
{
	// No generic trunk configured: this is the vendor-API anchor route it has
	// always been. respondIfDisconnected=false keeps the "rule matched but
	// nothing to route to" 404 with CallForker, which owns that tail.
	if (!_sipTrunk.config().valid())
	{
		return originateAnchorCall(data, caller, destination, /*respondIfDisconnected=*/false);
	}

	const std::string callID(data->getCallID());

	auto refuse = [&](const char* statusLine, const char* why) {
		auto msg = getMessageFromPool(*data);
		if (!msg) return;   // pool exhausted: drop, peer retransmits (#101A)
		msg->setHeader(statusLine);
		msg->clearBody();
		msg->setVia(sipwire::viaWithReceived(data->getVia(), data->getSource()));
		msg->setContact(buildContact(destination));
		_outbox.emplace_back(data->getSource(), std::move(msg));
		queueLog("trunk: " + std::string(why) + " for " + std::string(caller->getNumber())
			+ " -> " + destination, true);
	};

	// Cache-only lookup. resolve() would start a DNS job, and this runs on the
	// SIP thread under _mutex where a blocking getaddrinfo is exactly what
	// TrunkResolver exists to keep out. tick() is what refreshes the cache, so
	// steady state is a Hit and only the first call after boot can miss.
	sockaddr_in sbc{};
	const auto status = _trunkResolver.lookup(_sipTrunk.config().transportHost(),
		_sipTrunk.config().transportPort(), sbc, std::chrono::steady_clock::now());
	if (status != TrunkResolver::Status::Hit)
	{
		refuse("SIP/2.0 503 Service Unavailable", "SBC address not resolved yet");
		return true;
	}

	const int slot = findFreeTrunkRelay();
	if (slot < 0)
	{
		refuse("SIP/2.0 503 Service Unavailable", "every trunk relay pair busy");
		return true;
	}

	// Where the handset wants its audio. Read before anything is claimed: a
	// malformed offer costs nothing to refuse here and would otherwise leave a
	// started receiver to unwind.
	std::string handsetIp;
	uint16_t    handsetPort = 0;
	if (!parseCallerRtp(data, handsetIp, handsetPort))
	{
		refuse(SipMessageTypes::BAD_REQUEST, "no usable RTP destination in INVITE");
		return true;
	}

	sockaddr_in handsetRtp{};
	handsetRtp.sin_family = AF_INET;
	handsetRtp.sin_addr.s_addr = inet_addr(handsetIp.c_str());
	handsetRtp.sin_port = htons(handsetPort);

	// Bring up the carrier-facing half only. It needs to be bound before the
	// INVITE goes out because its port is what the SDP offer advertises, but it
	// has no peer yet -- we do not learn the carrier's RTP address until the
	// answer. Its raw sink already points at the handset-facing receiver, so
	// early media works the moment setRawPeer() lands on the far side; until
	// then sendRaw() drops for want of a peer, which is the intended
	// "drop, do not guess" behaviour.
	//
	// Null Sink: a relay never decodes. That is not an optimisation -- decoding
	// is what would hand a carrier IVR's keypress to the local star-code parser.
	if (!_handsetRx[slot].setRawPeer(handsetRtp))
	{
		refuse(SipMessageTypes::BAD_REQUEST, "handset RTP address is unusable");
		return true;
	}
	_trunkRx[slot].setRawSink(&trunkRelayForward, &_handsetRx[slot]);
	if (!_trunkRx[slot].start(0, nullptr))
	{
		releaseTrunkRelay(slot);
		refuse("SIP/2.0 500 Server Internal Error", "trunk relay receiver failed to start");
		return true;
	}

	auto newSession = allocateSession(callID, caller);
	if (!newSession)
	{
		releaseTrunkRelay(slot);
		refuse("SIP/2.0 503 Service Unavailable", "session pool full");
		return true;
	}

	// Per-session dummy dest, never a shared client, exactly as the anchor and
	// voicemail legs do -- a concurrent 777/440/888 call must not be able to
	// overwrite this call's destination identity, and the BYE/CANCEL leg-IP
	// check compares against its address.
	auto dummyTrunk = allocateVirtualPeer(kTrunkCallExt, data->getSource());
	if (!dummyTrunk)
	{
		releaseTrunkRelay(slot);
		refuse("SIP/2.0 503 Service Unavailable", "virtual-peer pool exhausted");
		return true;
	}
	newSession->setDest(dummyTrunk);
	newSession->setInviteMessage(data);
	newSession->setTrunk(true);
	newSession->setTrunkRelaySlot(slot);
	newSession->setState(Session::State::Invited);
	const std::string localTag = IDGen::GenerateID(9);
	newSession->setLocalTag(localTag);
	// Deliberately NO ring timer. SipTrunk::sweep() owns the no-answer deadline
	// for this call and fires onTrunkFailed(408) when it expires; arming the
	// session's own reaper as well would give one call two independent
	// teardowns racing each other.
	_sessions.emplace(callID, newSession);

	auto ringing = getMessageFromPool(*data);
	if (ringing)
	{
		ringing->setHeader(SipMessageTypes::RINGING);
		ringing->clearBody();
		ringing->setVia(sipwire::viaWithReceived(data->getVia(), data->getSource()));
		ringing->setTo(std::string(data->getTo()) + ";tag=" + localTag);
		ringing->setContact(buildContact(destination));
		_outbox.emplace_back(data->getSource(), std::move(ringing));
	}

	if (!_sipTrunk.placeCall(destination, callID, sbc,
		static_cast<uint16_t>(_trunkRx[slot].localPort())))
	{
		// Nothing reached the wire and no dialog slot was consumed (placeCall's
		// contract), so unwind everything this function claimed. endCall() is
		// what releases the relay, keyed on the session flag, so it does not
		// need repeating here.
		refuse("SIP/2.0 503 Service Unavailable", "trunk refused the call");
		endCall(callID, caller->getNumber(), destination, "trunk placeCall failed");
		return true;
	}

	queueLog("trunk: " + std::string(caller->getNumber()) + " -> " + destination
		+ " ringing (relay pair " + std::to_string(slot) + ")");
	return true;
}

// ── SipTrunk::Listener ───────────────────────────────────────────────────────

void RequestsHandler::onTrunkRinging(const SipTrunk::TrunkEvent& ev, bool earlyMedia)
{
	// The handset already got its 180 when the call was placed, so there is
	// nothing to forward. A 183 carries the carrier's SDP and could start early
	// media, which is deliberately deferred (see the issue): relaying it means
	// answering the handset's offer before the call is answered, and getting
	// that wrong leaves a connected-sounding call that never completes. Until
	// then the caller hears local ringback rather than the carrier's own
	// announcement, which is worth knowing when a SIT tone would have explained
	// a failure.
	if (earlyMedia)
	{
		queueLog("trunk: carrier signalled early media (183); not relayed yet, "
			"caller hears local ringback for " + std::string(ev.handsetCallID));
	}
}

void RequestsHandler::onTrunkAnswered(const SipTrunk::TrunkEvent& ev,
	const std::shared_ptr<SipMessage>& ok)
{
	const std::string handsetCallID(ev.handsetCallID);
	auto sit = _sessions.find(handsetCallID);
	if (sit == _sessions.end() || !sit->second) return;
	auto session = sit->second;
	const int slot = session->getTrunkRelaySlot();
	if (slot < 0) return;

	auto invite = session->getInviteMessage();
	if (!invite)
	{
		_sipTrunk.hangup(ev.trunkCallID);
		endCall(handsetCallID, session->getSrc() ? session->getSrc()->getNumber() : "",
			"", "trunk answered but the handset INVITE was not retained");
		return;
	}

	// Where the carrier wants its audio. Without this the relay has nowhere to
	// send and the call is one-way silence, so a failure here is fatal to the
	// call rather than something to log and continue past.
	std::string carrierIp;
	uint16_t    carrierPort = 0;
	if (!parseCallerRtp(ok, carrierIp, carrierPort))
	{
		_sipTrunk.hangup(ev.trunkCallID);
		refuseRingingTrunk(handsetCallID, 502);
		endCall(handsetCallID, invite->getFromNumber(), invite->getToNumber(),
			"carrier answer carried no usable RTP destination");
		return;
	}

	sockaddr_in carrierRtp{};
	carrierRtp.sin_family = AF_INET;
	carrierRtp.sin_addr.s_addr = inet_addr(carrierIp.c_str());
	carrierRtp.sin_port = htons(carrierPort);
	if (!_trunkRx[slot].setRawPeer(carrierRtp))
	{
		_sipTrunk.hangup(ev.trunkCallID);
		refuseRingingTrunk(handsetCallID, 502);
		endCall(handsetCallID, invite->getFromNumber(), invite->getToNumber(),
			"carrier RTP address is unusable");
		return;
	}

	// Bring up the handset-facing half and complete the cross-wiring. Started
	// only now because its bound port is what the 200 OK advertises, and there
	// was nothing to advertise it to until the call was answered.
	_handsetRx[slot].setRawSink(&trunkRelayForward, &_trunkRx[slot]);
	if (!_handsetRx[slot].start(0, nullptr))
	{
		_sipTrunk.hangup(ev.trunkCallID);
		refuseRingingTrunk(handsetCallID, 500);
		endCall(handsetCallID, invite->getFromNumber(), invite->getToNumber(),
			"handset relay receiver failed to start");
		return;
	}

	auto resp = getMessageFromPool(*invite);
	if (!resp)
	{
		// Pool exhausted with the carrier already answered: hang the carrier up
		// rather than leave a billing call with no handset attached to it.
		_sipTrunk.hangup(ev.trunkCallID);
		endCall(handsetCallID, invite->getFromNumber(), invite->getToNumber(),
			"message pool exhausted answering a trunk call");
		return;
	}

	// sendrecv: a trunk call is two-way, unlike 440's one-way tone. The DTMF
	// payload type is echoed from the HANDSET's own offer (RFC 3264: an answer
	// reuses the offerer's numbering), which is also what lets a keypress reach
	// the carrier at all -- the relay passes those packets through untouched.
	const std::string sdpBody = buildMediaSdp(_localIp, _handsetRx[slot].localPort(),
		/*sendrecv=*/true, invite->getTelephoneEventPayloadType());

	resp->setHeader(SipMessageTypes::OK);
	resp->setVia(sipwire::viaWithReceived(invite->getVia(), invite->getSource()));
	resp->setTo(std::string(invite->getTo()) + ";tag=" + session->getLocalTag());
	resp->setContact(buildContact(std::string(invite->getToNumber())));
	resp->setBody(sdpBody);   // resyncs Content-Length itself
	_outbox.emplace_back(invite->getSource(), std::move(resp));

	// Issue #232: this leg is server-terminated on the handset side, so this is
	// the only place its dialog identity is ever known. Without it a
	// server-initiated teardown cannot build a BYE toward the handset.
	session->setDialogHeaders(std::string(invite->getFrom()),
		std::string(invite->getTo()) + ";tag=" + session->getLocalTag());
	session->setState(Session::State::Connected);
	queueLog("trunk: call connected (relay pair " + std::to_string(slot) + ")");
}

void RequestsHandler::onTrunkFailed(const SipTrunk::TrunkEvent& ev, int status)
{
	const std::string handsetCallID(ev.handsetCallID);
	auto sit = _sessions.find(handsetCallID);
	if (sit == _sessions.end() || !sit->second) return;

	auto src  = sit->second->getSrc();
	auto inv  = sit->second->getInviteMessage();
	const std::string from = src ? std::string(src->getNumber())
		: (inv ? std::string(inv->getFromNumber()) : std::string());
	const std::string to   = inv ? std::string(inv->getToNumber()) : std::string();

	// Answer the still-ringing handset BEFORE tearing down: endCall() sends no
	// final response, so skipping this leaves the phone ringing at a call that
	// is already gone.
	refuseRingingTrunk(handsetCallID, status);
	endCall(handsetCallID, from, to,
		"trunk call failed (" + std::to_string(status) + ")");
}

void RequestsHandler::onTrunkRemoteBye(const SipTrunk::TrunkEvent& ev)
{
	const std::string handsetCallID(ev.handsetCallID);
	auto sit = _sessions.find(handsetCallID);
	if (sit == _sessions.end() || !sit->second) return;
	auto session = sit->second;

	auto src = session->getSrc();
	const std::string from = src ? std::string(src->getNumber()) : std::string();

	// The carrier hung up. BYE the handset off the dialog identity recorded
	// when we answered it (#232), then tear the call down the ordinary way.
	if (src && !session->getDialogFrom().empty() && !session->getDialogTo().empty())
	{
		auto bye = buildServerBye(std::string(src->getNumber()), src->getAddress(),
			handsetCallID, session->getDialogFrom(), session->getDialogTo());
		if (bye) _outbox.emplace_back(src->getAddress(), std::move(bye));
	}
	endCall(handsetCallID, from, "", "carrier hung up");
}
