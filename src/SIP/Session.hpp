#ifndef SESSION_HPP
#define SESSION_HPP

// Session.hpp: Issue #28 resolved.
#include <cstdint>
#include <memory>
#include <chrono>
#include <vector>

class SipMessage;
#include "SipClient.hpp"

class Session
{
public:

	enum class State : uint8_t
	{
		Invited,
		Busy,
		Unavailable,
		Cancel,
		Bye,
		Connected,
		// Mid-dialog hold (re-INVITE with a=sendonly/recvonly/inactive). Resuming
		// (Held -> Connected) preserves _startTime so CDR talk time spans the hold.
		Held,
	};


	Session();
	Session(std::string callID, std::shared_ptr<SipClient> src);

	void reset(std::string callID, std::shared_ptr<SipClient> src);

	void setState(State state);
	void setDest(std::shared_ptr<SipClient> dest);

	const std::string& getCallID() const;
	std::shared_ptr<SipClient> getSrc() const;
	std::shared_ptr<SipClient> getDest() const;
	State getState() const;
	std::chrono::steady_clock::time_point getStartTime() const;

	// The To-tag this UAS generated for the dialog. RFC 3261: the tag is created
	// once (on the first dialog-establishing response, our 180 Ringing) and MUST be
	// reused unchanged on the 200 OK. A fresh tag on the 200 makes it a different
	// dialog, which Yealink-class phones never reconcile — they keep ringing.
	const std::string& getLocalTag() const { return _localTag; }
	void setLocalTag(const std::string& tag) { _localTag = tag; }

	// Broadcast / Forking helpers
	bool isBroadcast() const { return _isBroadcast; }
	void setBroadcast(bool val) { _isBroadcast = val; }

	// True only for sessions bridged to the WAN media anchor (TelephonyAnchorClient
	// or LoopbackAnchorClient — ported from drawbridge, Stage B of the
	// TelephonyAnchorClient port). The anchor CallEvent callback and CANCEL/BYE
	// teardown branches MUST match on this — not on "dest is a non-pool client",
	// which is also true of the 777 echo, 440 tone, and 999/ring-group virtual
	// sessions and would make anchor teardown hit whichever virtual session
	// happened to be first in the map.
	bool isAnchor() const { return _isAnchor; }
	void setAnchor(bool val) { _isAnchor = val; }

	// True only for a session answered locally as voicemail (Issue #246,
	// answerVoicemailDeposit()) -- same reasoning as isAnchor() above: onBye()/
	// onCancel() must match on this, not on "dest is a non-pool client" or on
	// the dest's name, which is exactly the trap this class comment already
	// warns about for the OTHER locally-terminated legs (777/440/888/anchor).
	// Without this flag a voicemail leg's BYE falls through onBye()'s generic
	// two-real-phone path, which RELAYS the BYE toward the mailbox owner's own
	// extension instead of the server answering it directly -- the caller who
	// left the message never gets their 200 OK.
	bool isVoicemail() const { return _isVoicemail; }
	void setVoicemail(bool val) { _isVoicemail = val; }

	// Which _vmLegs[]/_vmRtpReceivers[]/_vmRtpSenders[] slot this session
	// claimed (-1 if none) -- onBye()/onCancel() need this to release the
	// slot back to the pool; VoicemailLeg itself carries no callId until
	// startRecording()/startPlaying() is called on it, so the session is the
	// only place this identity lives in the meantime.
	int getVoicemailLegSlot() const { return _voicemailLegSlot; }
	void setVoicemailLegSlot(int slot) { _voicemailLegSlot = slot; }

	// Deposit (leaving a message) vs Retrieval (checking the mailbox) --
	// both answer locally and both use VoicemailLeg's Playing/PlaybackDone
	// states, but tick()'s sweep must only auto-advance Playing ->
	// Recording for a Deposit leg's greeting. A Retrieval leg's own
	// menu state machine decides what PlaybackDone means for it instead
	// (advance to the next prompt, wait for a keypress, etc.) -- the sweep
	// must never race that decision.
	enum class VoicemailPurpose : uint8_t { Deposit, Retrieval };
	VoicemailPurpose getVoicemailPurpose() const { return _voicemailPurpose; }
	void setVoicemailPurpose(VoicemailPurpose p) { _voicemailPurpose = p; }

	// Wall-clock safety net for an in-progress Deposit recording, in case the
	// caller's audio silently stops arriving (a network drop, a phone that
	// stops sending RTP) without ever hitting onCallerRtp()'s byte-cap or a
	// BYE. Deliberately separate from armRingTimer()/isRingExpired() above --
	// that pair is a PRE-answer ring timeout; this is a POST-answer one, and
	// reusing the same name/fields for both would confuse a future reader
	// checking which applies to an already-Connected call.
	void armVoicemailDeadline(std::chrono::steady_clock::time_point deadline)
	{
		_voicemailDeadline = deadline;
		_voicemailDeadlineArmed = true;
	}
	bool isVoicemailDeadlineExpired(std::chrono::steady_clock::time_point now) const
	{
		return _voicemailDeadlineArmed && now >= _voicemailDeadline;
	}

	// Inbound anchor calls invert the SIP roles of an outbound one: the server is the
	// UAC that originated the INVITE *toward the handset* (dest), so teardown/ACK must
	// address the handset and carry our From-tag. These fields hold the extra dialog
	// state an inbound leg needs that an outbound (server-as-UAS) leg does not:
	//   _remoteTag           — the handset's To-tag, learned from its 200 OK
	//   _uacBranch           — the Via branch of our INVITE (reused for the CANCEL)
	//   _anchorParticipantId — the upstream participant id to answerCall()/dropCall()
	bool isAnchorInbound() const { return _anchorInbound; }
	void setAnchorInbound(bool val) { _anchorInbound = val; }
	const std::string& getRemoteTag() const { return _remoteTag; }
	void setRemoteTag(const std::string& tag) { _remoteTag = tag; }
	const std::string& getUacBranch() const { return _uacBranch; }
	void setUacBranch(const std::string& branch) { _uacBranch = branch; }
	const std::string& getAnchorParticipantId() const { return _anchorParticipantId; }
	void setAnchorParticipantId(const std::string& id) { _anchorParticipantId = id; }

	const std::vector<std::shared_ptr<SipClient>>& getPendingTargets() const { return _pendingTargets; }
	void setPendingTargets(std::vector<std::shared_ptr<SipClient>> targets) { _pendingTargets = std::move(targets); }
	void removePendingTarget(const std::string& number);

	std::shared_ptr<SipMessage> getInviteMessage() const { return _inviteMessage; }
	void setInviteMessage(std::shared_ptr<SipMessage> msg) { _inviteMessage = msg; }

	// ── No-answer / hunt-group timer (Class A sweep) ──────────────────
	// A non-default _ringDeadline arms a one-shot timer that tick() polls: on
	// expiry the registrar CANCELs the outstanding leg and advances (CFNA forward,
	// or the next hunt member). hasRingTimer()/isRingExpired() are pure queries;
	// clearRingTimer() disarms it once the call connects or is torn down.
	void armRingTimer(std::chrono::steady_clock::time_point deadline) { _ringDeadline = deadline; _ringTimerArmed = true; }
	void clearRingTimer() { _ringTimerArmed = false; }
	bool hasRingTimer() const { return _ringTimerArmed; }
	bool isRingExpired(std::chrono::steady_clock::time_point now) const { return _ringTimerArmed && now >= _ringDeadline; }

	// CFNA forward target: where to send the call when the no-answer timer fires.
	const std::string& getNoAnswerTarget() const { return _noAnswerTarget; }
	void setNoAnswerTarget(const std::string& t) { _noAnswerTarget = t; }

	// ── Sequential hunt-group progression (Class A sweep) ─────────────
	// _huntMembers is the ordered list; _huntIndex is the member currently ringing.
	// _huntActive distinguishes a hunt session from an ordinary/broadcast one.
	bool isHunt() const { return _huntActive; }
	void setHunt(bool v) { _huntActive = v; }
	std::vector<std::string>& getHuntMembers() { return _huntMembers; }
	void setHuntMembers(std::vector<std::string> m) { _huntMembers = std::move(m); }
	size_t getHuntIndex() const { return _huntIndex; }
	void setHuntIndex(size_t i) { _huntIndex = i; }

	// The group extension this fork is servicing (for CDR / logging), if any.
	const std::string& getGroupExt() const { return _groupExt; }
	void setGroupExt(const std::string& g) { _groupExt = g; }

	// ── Call parking (park-orbit bridge) ──────────────────────────────
	// peerCallID links the two dialog legs of a retrieved (or rung-back) parked
	// call so a BYE from either side relays a server BYE to the other leg.
	// parkUac marks the leg the SERVER originated (the park-timeout ring-back
	// INVITE toward the parker), which inverts the From/To roles of that relay.
	const std::string& getPeerCallID() const { return _peerCallID; }
	void setPeerCallID(const std::string& id) { _peerCallID = id; }
	bool isParkUac() const { return _parkUac; }
	void setParkUac(bool v) { _parkUac = v; }

	// ── RFC 4028 session timers ────────────────────────────────────────
	// _sessionExpiresSeconds != 0 means "an expiry reaper is armed for this
	// dialog" — RequestsHandler::sweepSessionTimers() keys off exactly that.
	// It is NOT the same as "the endpoints negotiated a session timer":
	// RequestsHandler::armSessionTimer() deliberately declines to arm when the
	// 2xx names no refresher, because nothing would then be obliged to feed it.
	uint32_t getSessionExpiresSeconds() const { return _sessionExpiresSeconds; }
	// Whether THIS PBX is the RFC 4028 refresher. On the ordinary call path it
	// never is — the PBX relays the caller's INVITE rather than originating one,
	// so the "uac"/"uas" of §7.4 are the two phones and neither is us. See
	// RequestsHandler::armSessionTimer()'s derivation. Kept as state because a
	// future server-as-UAC leg (anchor/park) could legitimately set it.
	bool isRefresher() const { return _isRefresher; }
	// Half the negotiated interval, per RFC 4028 §10's refresh-at-half rule.
	// DORMANT: nothing consumes this, because no code path generates a
	// refreshing re-INVITE or UPDATE. Anything that starts reading it must ship
	// the sender alongside, or it recreates #198 from the other direction.
	std::chrono::steady_clock::time_point getNextRefresh() const { return _nextRefresh; }
	std::chrono::steady_clock::time_point getSessionExpiry() const { return _sessionExpiry; }
	void armSessionTimer(uint32_t secs, bool weAreRefresher,
	                     std::chrono::steady_clock::time_point now) {
		_sessionExpiresSeconds = secs;
		_isRefresher = weAreRefresher;
		_sessionExpiry = now + std::chrono::seconds(secs);
		_nextRefresh   = now + std::chrono::seconds(secs / 2);
	}
	void setNextRefresh(std::chrono::steady_clock::time_point t) { _nextRefresh = t; }
	const std::string& getDialogFrom() const { return _dialogFrom; }
	const std::string& getDialogTo()   const { return _dialogTo;   }
	void setDialogHeaders(std::string from, std::string to) {
		_dialogFrom = std::move(from);
		_dialogTo   = std::move(to);
	}

	// The callee's most recent SDP (from its 200 OK to the initial INVITE or any
	// re-INVITE). Used by attended transfer to cross-connect two live dialogs.
	const std::string& getRemoteSdp() const { return _remoteSdp; }
	void setRemoteSdp(std::string s) { _remoteSdp = std::move(s); }

	// Marks a session as one half of an attended-transfer bridge. The BYE relay
	// uses getPeerCallID() to reach the other half and getDialogFrom/To() for
	// correct in-dialog headers (rather than the park-bridge logic).
	bool isTransferBridge() const { return _isTransferBridge; }
	void setTransferBridge(bool v) { _isTransferBridge = v; }

	// Whether the transferor (A) was THIS dialog's caller (src) or callee
	// (dest) at splice time. The splice deliberately leaves src/dest
	// unchanged (swapping them would corrupt CDR caller/callee and
	// getRemoteSdp()'s "callee's SDP" meaning), so the surviving non-A party
	// can be getSrc() OR getDest() depending on which side A originally was
	// -- meaningful only when isTransferBridge() is true. Same
	// role-inversion reasoning as isParkUac() above.
	bool wasTransferorSrc() const { return _wasTransferorSrc; }
	void setWasTransferorSrc(bool v) { _wasTransferorSrc = v; }

	// Marks the leg a BLIND transfer creates toward the transfer target (issue
	// #197). The server is the UAC on it — it minted the INVITE, impersonating
	// the transferee whose media it carries — so every response on this dialog
	// belongs to US, never to the transferee: a 200 OK must be ACKed here and
	// turned into a re-INVITE of the transferee (not relayed as if it answered
	// something), and a 180/4xx/5xx/6xx must not be forwarded into the
	// transferee's own dialog, whose Call-ID and tags it does not match.
	// Distinct from isParkUac() (a park ring-back, a different role inversion)
	// and from isTransferBridge(), which this leg ALSO becomes once the target
	// answers and the two dialogs are linked.
	bool isBlindXferLeg() const { return _blindXferLeg; }
	void setBlindXferLeg(bool v) { _blindXferLeg = v; }

	// Issue #257. When the server impersonates the transferor (A) inside this
	// dialog -- the blind-transfer swap re-INVITE toward the transferee -- the
	// CSeq it mints MUST be higher than any CSeq this dialog has already seen
	// from A's own UA, or the transferee's stack correctly rejects it with 500
	// Invalid CSeq (RFC 3261 s12.2.2). A hardcoded low constant broke on any
	// real UA whose dialog CSeq had already climbed past it -- which is most
	// of them; there is no reason a phone's own CSeq counter starts near 1.
	//
	// The REFER that starts a blind transfer is itself an in-dialog request
	// from A on THIS dialog, so it is a real, fresh, directly-observed data
	// point for "the last CSeq A used here" -- captured once at REFER time
	// (there is no ongoing per-message tracking; nothing else needs this
	// value or updates it). 0 means unset/never captured.
	uint32_t transferorCseqAtRefer() const { return _transferorCseqAtRefer; }
	void setTransferorCseqAtRefer(uint32_t v) { _transferorCseqAtRefer = v; }

	void release();

private:
	std::string _callID;
	std::shared_ptr<SipClient> _src;
	std::shared_ptr<SipClient> _dest;
	State _state;
	std::chrono::steady_clock::time_point _startTime;

	std::string _localTag; // UAS-generated To-tag, shared across 180 + 200 OK

	bool _isBroadcast = false;
	bool _isAnchor = false;
	bool _isVoicemail = false;
	int  _voicemailLegSlot = -1;
	VoicemailPurpose _voicemailPurpose = VoicemailPurpose::Deposit;
	std::chrono::steady_clock::time_point _voicemailDeadline;
	bool _voicemailDeadlineArmed = false;
	bool _anchorInbound = false;
	std::string _remoteTag;            // handset To-tag (inbound anchor leg)
	std::string _uacBranch;            // our INVITE Via branch (inbound anchor leg)
	std::string _anchorParticipantId;  // upstream participant id (either anchor direction)
	std::vector<std::shared_ptr<SipClient>> _pendingTargets;
	std::shared_ptr<SipMessage> _inviteMessage;

	// No-answer / hunt timer + forwarding/hunt bookkeeping (Class A sweep).
	std::chrono::steady_clock::time_point _ringDeadline;
	bool _ringTimerArmed = false;
	std::string _noAnswerTarget;

	bool _huntActive = false;
	std::vector<std::string> _huntMembers;
	size_t _huntIndex = 0;

	std::string _groupExt;

	// Call parking (park-orbit bridge): linked peer leg + server-as-UAC marker.
	std::string _peerCallID;
	bool _parkUac = false;

	// RFC 4028 session timers. 0 = not negotiated.
	uint32_t _sessionExpiresSeconds = 0;
	bool _isRefresher = false;
	std::chrono::steady_clock::time_point _nextRefresh{};
	std::chrono::steady_clock::time_point _sessionExpiry{};
	// From/To dialog headers (with tags) captured from the 200 OK that established
	// the call — used to build server-originated BYEs on session timer expiry.
	std::string _dialogFrom;
	std::string _dialogTo;

	std::string _remoteSdp;        // callee's most recent SDP (for transfer SDP swap)
	bool _isTransferBridge = false; // true for attended-transfer bridge halves
	bool _blindXferLeg = false;    // true for the server-UAC leg toward a blind-transfer target
	bool _wasTransferorSrc = true; // meaningful only when _isTransferBridge
	uint32_t _transferorCseqAtRefer = 0; // issue #257, see the accessor's comment
};

#endif
