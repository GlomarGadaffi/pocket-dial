#ifndef SIP_TRUNK_HPP
#define SIP_TRUNK_HPP

#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>

#include "PbxEnv.hpp"
#include "PoolConfig.hpp"
#include "SipMessage.hpp"

// ── Generic ITSP SIP trunk, outbound half (issue #164) ───────────────────────
//
// A UAC dialog toward a carrier's SBC, spoken in plain SIP over UDP: INVITE out,
// ACK the answer, BYE to hang up. No vendor SDK, no REST control plane. This is
// what most of the industry actually offers, and until now the only PSTN
// interconnect this firmware had was TelephonyAnchorClient -- a 3CX Call Control
// API client, which only works against a provider exposing that specific API.
//
// ── Why this is NOT an AnchorClient ──────────────────────────────────────────
//
// Issue #164's own text proposes building this behind the existing
// AnchorClient/MediaBridge extension point. That does not work, and the reason
// is worth stating where someone will read it before trying again:
//
//   AnchorClient is a PCM-16 AUDIO contract. RFC 4733 telephone-event packets
//   have no representation in writeAudio()/AudioRxCallback -- there is no
//   method on that interface by which a DTMF digit could be carried. A trunk
//   whose media went through it would decode the carrier's telephone-event
//   packets to PCM16 and re-encode, destroying them. DTMF would never reach the
//   carrier, so no IVR, no calling card, no conference bridge PIN.
//
// So: signaling here, as a dialog reusing TransactionLayer (which picks the
// dialog up structurally -- see below); media as a SEPARATE RtpReceiver/RtpSender
// pair running in RAW RELAY (RtpReceiver::setRawSink), forwarding µ-law and
// telephone-event alike, byte for byte, without interpreting either.
//
// ── The star-code hazard, and why it cannot bite here ────────────────────────
//
// A relay leg must never decode DTMF locally: this PBX feeds decoded digits to
// its star-code feature parser, so a caller pressing "1" at a carrier IVR would
// trip a local feature code instead of reaching the carrier. That cannot happen
// by construction, on two independent grounds, and neither relies on this class
// remembering to be careful:
//
//   1. RtpReceiver's RFC 4733 path is inert unless armed. _dtmfPt defaults to
//      kDtmfPayloadTypeUnset and dispatchDtmf() returns at its first guard. The
//      only caller that arms it is MediaBridge, which is only init()ed for
//      anchor and conference legs. This class never calls setDtmfPayloadType().
//   2. RtpReceiver::setRawSink() is EXCLUSIVE -- an armed raw sink claims the
//      packet and runLoop() skips the audio sink and the RFC 4733 decode
//      entirely. There is no state in which one receiver both relays and
//      interprets.
//
// ── Transaction coverage comes for free ──────────────────────────────────────
//
// Nothing here schedules a retransmit. Every message is handed to
// PbxEnv::enqueue(), and TransactionLayer::maybeTrack() runs over each outbox
// entry as it is flushed -- so the INVITE gets Timer A/B and the BYE gets Timer
// E/F without this class knowing the transaction layer exists. Deliberately the
// same arrangement RegisterBeeper uses. Do NOT add a retry schedule here; two
// schedules on one request put two copies on the wire per loss.
//
// ── Bounded, no hot-path heap ────────────────────────────────────────────────
//
// Dialogs live in a fixed array sized by POCKETDIAL_MAX_TRUNK_CALLS. Out of
// slots means the call is refused, not queued -- an outbound PSTN call that
// cannot be placed must fail fast and audibly, not sit in a queue the caller
// cannot see. Matches the pool-exhaustion posture everywhere else in this
// engine (CONTRIBUTING_FIRMWARE rule 1: no allocation in RTOS tasks after init).
//
// Locking: every method assumes the caller holds the engine's _mutex, matching
// the convention of the sibling machine classes.
class SipTrunk
{
public:
	explicit SipTrunk(PbxEnv& env) : _env(env) {}

	// ── Configuration ────────────────────────────────────────────────────────
	//
	// Bounded fixed-capacity strings rather than std::string, for the same reason
	// the rest of the config surface uses them: this is written from the HTTP
	// thread and read from the SIP thread, and a std::string reallocating under a
	// concurrent read is a use-after-free that only shows up under load.
	struct Config
	{
		// The carrier SBC. `host` may be a dotted quad or an FQDN -- resolution is
		// NOT done here (getaddrinfo is untimed-blocking under lwIP and must never
		// run on the SIP thread); the caller hands placeCall() an already-resolved
		// address.
		char     host[64]  = {};
		uint16_t port      = 5060;

		// The identity presented to the carrier. `fromUser` is typically the
		// trunk's main DID or the auth username; it is what appears in the From
		// URI and is what most carriers match against when deciding whether to
		// accept the call at all.
		char fromUser[40]  = {};

		// The DID presented as caller ID. Separate from fromUser because carriers
		// commonly allow a range of outbound CLIs against one authenticated
		// identity. Empty means "use fromUser".
		char callerId[24]  = {};

		bool enabled = false;

		bool valid() const { return enabled && host[0] != '\0' && port != 0 && fromUser[0] != '\0'; }
	};

	void setConfig(const Config& cfg) { _cfg = cfg; }
	const Config& config() const { return _cfg; }

	// ── Dialog state ─────────────────────────────────────────────────────────
	//
	// Trying      : INVITE sent, nothing back yet.
	// Proceeding  : a 1xx arrived. 180 and 183 both land here; the distinction is
	//               recorded in `sawSessionProgress` because 183 means the carrier
	//               is sending EARLY MEDIA (ringback, or a SIT tone explaining why
	//               the call is failing) and the relay has to be live to hear it,
	//               whereas 180 means generate local ringback.
	// Confirmed   : 2xx received and ACKed -- the call is up.
	// Terminating : BYE sent, waiting for its 200.
	enum class State : uint8_t { Free, Trying, Proceeding, Confirmed, Terminating };

	struct Dialog
	{
		State state = State::Free;

		// Dialog identifiers (RFC 3261 §12). `toTag` is empty until a response
		// that carries one arrives; an in-dialog request without it is malformed,
		// which is why buildBye() refuses to build one.
		std::string callID;
		std::string branch;     // the INVITE's Via branch; ACK for a non-2xx reuses it
		std::string fromTag;
		std::string toTag;
		uint32_t    cseq = 1;

		// Where the request-URI and Via point.
		// The identity stamped into From and Contact. Captured per dialog rather
		// than read from Config at build time: it keeps the builders pure, and it
		// means a config edit mid-call cannot retag an in-flight dialog's From --
		// which would break the carrier's dialog matching and orphan the BYE.
		std::string fromUser;

		std::string sbcIpPort;
		std::string localIpPort;
		std::string destE164;

		// The far end's Contact from the 2xx, which is where in-dialog requests
		// (the BYE) must go -- NOT the SBC address the INVITE was sent to. Many
		// carriers answer from a different media/signaling node than the one that
		// took the INVITE, and a BYE sent to the wrong one is simply ignored,
		// leaving the call up and billing.
		std::string remoteTarget;

		// The handset leg this trunk call is bridged to, so a teardown on either
		// side can find the other.
		std::string handsetCallID;

		uint16_t localRtpPort = 0;
		bool     sawSessionProgress = false;   // a 183 arrived: early media is live

		sockaddr_in peer{};
		std::chrono::steady_clock::time_point deadline{};
	};

	// ── Pure builders ────────────────────────────────────────────────────────
	//
	// Static and free of engine state so the wire format is host-testable without
	// standing up a PBX. This is where trunk bugs actually live -- a carrier that
	// rejects a call over a malformed Contact or a missing rtpmap gives you a 4xx
	// and nothing else to go on.

	// The outbound INVITE, with `sdp` as its body. Content-Length is written from
	// sdp.size(); the caller still calls syncContentLength() after pooling, for
	// the same reason RegisterBeeper does -- a wrong Content-Length silently
	// truncates the offer on UDP and the carrier answers 400.
	static std::string buildInvite(const Dialog& d, const std::string& sdp);

	// ACK for a 2xx (RFC 3261 §13.2.2.4): a NEW transaction with a fresh branch,
	// sent to the dialog's remote target, carrying the To-tag from the answer.
	//
	// Distinct from ackForFailure() on purpose. Conflating the two is the classic
	// trunk bug: an ACK for a non-2xx belongs to the INVITE's own transaction and
	// MUST reuse its branch (§17.1.1.3), while an ACK for a 2xx is a new
	// transaction routed to the Contact. Sending the §17.1.1.3 form for a 200 is
	// the "carrier keeps retransmitting the 200 and then drops the call" failure.
	//
	// `freshBranch` is a parameter rather than generated inside, so this stays a
	// pure function the host tests can pin byte for byte. A builder reaching for
	// IDGen internally would return a different string every call and could only
	// be checked by regex -- too loose for a wire format a carrier will reject.
	static std::string buildAckFor2xx(const Dialog& d, std::string_view freshBranch);

	// ACK for a 3xx-6xx final response. Same branch as the INVITE, sent to the
	// address the INVITE went to, no body.
	static std::string buildAckForFailure(const Dialog& d);

	// In-dialog BYE toward the remote target. Returns an empty string when the
	// dialog has no To-tag or no remote target -- there is no such thing as a
	// well-formed in-dialog request without them, and emitting a half-formed BYE
	// would earn a 481 while leaving the call up.
	static std::string buildBye(const Dialog& d, std::string_view freshBranch);

	// ── Listener: how the engine learns a trunk dialog moved ─────────────────
	//
	// Every callback fires on the SIP thread, synchronously, from inside the
	// method that observed the change -- so the engine's _mutex is already held
	// and no queue is involved. That is the whole reason this is a raw pointer
	// set once at init rather than anything heap-backed.
	//
	// The listener is handed a TrunkEvent, never the Dialog itself. The Dialog
	// lives in a fixed slot this class recycles, and a listener is EXPECTED to
	// call back in -- brief §3 has it calling hangup() when the answer's SDP is
	// unusable. Handing out a reference to a slot the callback may cause to be
	// rewritten is a dangling-reference bug waiting for a state-machine change
	// to expose it, so the callback gets copies of the scalars and views of the
	// strings it actually needs, and nothing else.
	struct TrunkEvent
	{
		std::string_view trunkCallID;     // the trunk dialog's own Call-ID
		std::string_view handsetCallID;   // the bridged handset leg, for session lookup
		uint16_t         localRtpPort = 0;
	};

	// The views above point either into the live dialog slot or into a local
	// the caller owns for the duration of the call. Either way they are valid
	// for THE CALLBACK'S DURATION ONLY. A listener that needs to keep one must
	// copy it into its own storage; storing the view is a use-after-free the
	// moment the slot is reused.
	struct Listener
	{
		virtual ~Listener() = default;

		// 180, or 183 with earlyMedia=true. Nothing is relayed yet either way:
		// a 183's SDP is not read here (see the class note on staying
		// SDP-ignorant), so the caller hears silence rather than the carrier's
		// announcement until early media is wired as a follow-up.
		virtual void onTrunkRinging(const TrunkEvent& ev, bool earlyMedia) = 0;

		// Fired AFTER the ACK is enqueued and the dialog reads Confirmed, so a
		// listener that immediately hangs up produces ACK-then-BYE on the wire,
		// which is the only ordering a carrier will accept.
		virtual void onTrunkAnswered(const TrunkEvent& ev,
			const std::shared_ptr<SipMessage>& ok) = 0;

		// A 3xx-6xx final to our INVITE, or a sweep timeout (status 408). Fired
		// AFTER the slot has been released, so the listener may place a fresh
		// call from inside it.
		virtual void onTrunkFailed(const TrunkEvent& ev, int status) = 0;

		// The carrier hung up first. Fired after the 200 is enqueued and the
		// slot released. Deliberately NOT fired when OUR OWN BYE completes --
		// the listener already tore the handset down when it called hangup(),
		// and firing here would BYE it a second time.
		virtual void onTrunkRemoteBye(const TrunkEvent& ev) = 0;
	};

	// Set once at init. Raw pointer, no ownership, no heap: the listener is the
	// engine itself and outlives this object.
	void setListener(Listener* l) { _listener = l; }

	// ── Engine-facing operations ─────────────────────────────────────────────

	// Place an outbound call to `e164` over the trunk. `sbc` is the already
	// resolved SBC address (see Config::host on why resolution is not done here),
	// `localRtpPort` the port the trunk's relay receiver is bound on.
	//
	// Returns false when the trunk is disabled or unconfigured, when no dialog
	// slot is free, or when the message pool is exhausted. A false return means
	// nothing was sent and no slot was consumed.
	bool placeCall(std::string_view e164, std::string_view handsetCallID,
		const sockaddr_in& sbc, uint16_t localRtpPort);

	// Does this Call-ID belong to a live trunk dialog? Recognition only.
	bool ownsCallID(std::string_view callID) const;

	// Route a response for one of our dialogs. Returns true if consumed, in which
	// case the caller must not process it further.
	bool handleResponse(const std::shared_ptr<SipMessage>& data);

	// The carrier hanging up first. Answers 200, releases the dialog and tells
	// the listener, which is what BYEs the handset leg.
	//
	// Returns false for anything that is not an in-dialog BYE we recognise, so
	// the engine can carry on treating it as an ordinary request. Recognition
	// is by Call-ID alone: the carrier is not a registered client, so none of
	// the registrar-backed authorisation the handset paths use applies here,
	// and the Call-ID of a live trunk dialog is the only thing that identifies
	// it. That is the same basis ownsCallID() already answers on.
	bool handleBye(const std::shared_ptr<SipMessage>& data);

	// Tear down the trunk leg for `callID` (either the trunk's own Call-ID or the
	// handset leg's). Sends a BYE if the dialog is confirmed; frees it outright if
	// it never got that far. Returns true if a dialog was found.
	bool hangup(std::string_view callID);

	// Time out dialogs that never reached a final response.
	void sweep(std::chrono::steady_clock::time_point now);

	// Test/diagnostic accessors. Cheap linear scans over a fixed array.
	size_t activeDialogs() const;

	// Force every live dialog's deadline into the past. Test-only: sweep()
	// reads steady_clock and there is no injectable clock in this engine, so
	// the alternative to this is a test that really waits 60 seconds.
	void expireDeadlinesForTest();
	const Dialog* findByCallID(std::string_view callID) const;

private:
	Dialog* findMutableByCallID(std::string_view callID);
	Dialog* allocDialog();

	// Fill a TrunkEvent from a dialog. Views borrow that dialog's storage, so
	// the result must not outlive it -- see the Listener note.
	static TrunkEvent eventFor(const Dialog& d)
	{
		return TrunkEvent{ d.callID, d.handsetCallID, d.localRtpPort };
	}

	PbxEnv& _env;
	Config  _cfg{};
	Listener* _listener = nullptr;
	std::array<Dialog, POCKETDIAL_MAX_TRUNK_CALLS> _dialogs{};
};

#endif // SIP_TRUNK_HPP
