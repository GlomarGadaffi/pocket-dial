#ifndef REGISTER_BEEPER_HPP
#define REGISTER_BEEPER_HPP

#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>

#include "PbxEnv.hpp"
#include "PoolConfig.hpp"
#include "SipClient.hpp"
#include "SipMessage.hpp"

// ── Register beep (signaling-only intercom tone) ──────────────────────────────
// On a NEW registration, send the registering phone a brief auto-answer INVITE
// so it plays its own intercom tone (the "beep"), then tear the call straight
// back down. NO RTP is ever sourced — the tone is the phone's local intercom
// alert. Each outbound UAC dialog lives in a small bounded ring keyed by
// Call-ID so handleOk() can drive ACK→BYE and sweep() can time it out / CANCEL
// it.
//
// State machine (per beep dialog):
//   sendBeep()             : allocate a slot, send INVITE (auto-answer headers),
//                            arm a deadline; if no slot free, skip the beep (it's
//                            cosmetic).
//   handleOk() INVITE 200  : send ACK, then BYE, advance to AwaitingByeOk. Matches
//                            from AwaitingInviteOk OR AwaitingCancelDone — RFC 3261
//                            §9.1 lets this 200 race an in-flight CANCEL, and a
//                            raced answer still needs ACK+BYE.
//   handleOk() BYE 200     : free the slot.
//   sweep() deadline       : if AwaitingInviteOk, CANCEL and move to
//                            AwaitingCancelDone (NOT freed yet — see above) with a
//                            fresh bounded deadline. If AwaitingByeOk or
//                            AwaitingCancelDone, just free (best-effort BYE already
//                            sent, or the fallback window on a raced CANCEL expired
//                            with no further response). The dialog's own 487, when
//                            the CANCEL did land in time, no longer relies on that
//                            fallback: RequestsHandler::onReqTerminated now offers
//                            every 487 to handleInviteFailure() first, so it is
//                            ACKed and the slot released on arrival. The deadline
//                            is the belt-and-suspenders path for a 487 that never
//                            comes at all.
//
// Locking: every method assumes the caller holds the engine's _mutex
// (non-recursive), matching the RequestsHandler code this was extracted from.
class RegisterBeeper
{
public:
	explicit RegisterBeeper(PbxEnv& env) : _env(env) {}

	// Issue #408: how long after a REGISTER's 200 OK the register beep goes out.
	// Sent in the same pass as the 200, it reached phones that had just sent
	// their REGISTER during their own startup and were not ready for a call yet
	// (pjsua answers 503 until it is RUNNING; a real handset after a reboot can
	// be in the same window). Fired from sweep(), i.e. from tick() (<= 1 Hz),
	// so the real delay is this plus up to one tick.
	static constexpr std::chrono::milliseconds kAfterRegisterDelay{500};

	// Kick off a beep dialog toward a phone. Bounded and best-effort — if the
	// table is full the beep is simply skipped. delay 0 sends now (the E911
	// alert path); a non-zero delay parks the slot as Pending and sweep()
	// sends it once the delay has passed (the register path, #408).
	void sendBeep(const std::shared_ptr<SipClient>& phone,
		std::chrono::milliseconds delay = std::chrono::milliseconds(0));

#if !defined(ESP_PLATFORM) && !defined(ESP32) && !defined(ARDUINO)
	// Test-only (#408): send every Pending beep now, whatever its deadline, so a
	// handler-level test need not wait out kAfterRegisterDelay.
	void firePendingNowForTest(std::chrono::steady_clock::time_point now)
	{
		for (auto& bd : _dialogs)
		{
			if (bd.state == BeepState::Pending) fire(bd, now);
		}
	}
#endif

	// Route a 200 OK that belongs to a beep dialog (matched by Call-ID). Returns
	// true if the response was consumed (the caller must not process it further).
	bool handleOk(const std::shared_ptr<SipMessage>& data);

	// Route a NON-2xx final response to our beep INVITE (matched by Call-ID):
	// ACK it and free the slot. Returns true if the response was consumed.
	//
	// RFC 3261 §17.1.1.3 makes the ACK mandatory — without it the phone's server
	// transaction keeps retransmitting its failure response until Timer H (~32 s).
	// Worse, this dialog previously sat in AwaitingInviteOk until sweep()'s
	// deadline and then sent a CANCEL, which §9.1 forbids once a final response
	// has arrived; the phone answers that with 481 and the slot stays pinned for
	// the whole window. A phone can legitimately reject the beep (a 4xx it does
	// not like, 488, 606), so this is an ordinary path, not an error path.
	bool handleInviteFailure(const std::shared_ptr<SipMessage>& data);

	// Does this Call-ID belong to a live beep dialog? Recognition only: nothing is
	// ACKed, no slot is released, no state moves.
	//
	// This exists SEPARATELY from handleInviteFailure() because a 1xx is
	// provisional (RFC 3261 §17.1.1) — it neither takes an ACK nor ends the
	// INVITE transaction, so a beep dialog that has merely been answered with
	// 180 Ringing is still very much alive and must keep its slot. The only
	// thing its handler needs is to know the response is OURS and stop, instead
	// of relaying it by the beep's own From ("pbx"), which is not a registered
	// extension and so came back at the phone as a 404 (drawbridge #178).
	// Do NOT "simplify" a provisional caller into handleInviteFailure(): that
	// would ACK a response the RFC says takes none and free a dialog whose
	// INVITE is still outstanding.
	bool ownsCallID(std::string_view callID);

	// Time out overdue dialogs: CANCEL an unanswered INVITE (see sweep()'s own
	// comment for why the slot isn't freed immediately), free a slot whose
	// bounded fallback window has expired either way.
	void sweep(std::chrono::steady_clock::time_point now);

private:
	// AwaitingCancelDone: CANCEL sent for an unanswered INVITE, lingering for a
	// bounded window in case the phone's 200 OK raced the CANCEL (RFC 3261 §9.1) —
	// handleOk() still matches this state so a raced answer gets ACKed+BYEd.
	// Pending (#408): slot claimed, INVITE not sent yet; sweep() sends it at the
	// deadline. It has no Call-ID yet, so no response can match it.
	enum class BeepState : uint8_t { Free, Pending, AwaitingInviteOk, AwaitingByeOk, AwaitingCancelDone };
	struct BeepDialog
	{
		BeepState state = BeepState::Free;
		std::string callID;        // fresh per beep; how handleOk()/sweep() find this slot
		std::string branch;        // Via branch (reused for INVITE/CANCEL)
		std::string fromTag;       // our (server) From tag
		std::string ext;           // target extension (phone number)
		std::string requestUri;    // the phone's registered Contact URI (#856); INVITE/ACK/CANCEL go to it
		sockaddr_in addr{};        // phone's contact address
		std::chrono::steady_clock::time_point deadline{};
		// Issue #104: counts consecutive buildCancel() failures (message-pool
		// exhaustion) in AwaitingInviteOk. sweep() retries on a short delay
		// rather than freeing the slot immediately, but bounded — past
		// kMaxCancelRetries the slot is freed like any other abandoned dialog
		// instead of retrying forever under sustained pool pressure.
		int cancelRetries = 0;
	};

	BeepDialog* findByCallID(std::string_view callID);
	// Build and send the INVITE for a claimed slot (its ext/addr already set),
	// moving it to AwaitingInviteOk with the 5 s answer deadline.
	void fire(BeepDialog& slot, std::chrono::steady_clock::time_point now);
	// Free this dialog's INVITE transaction, then clear the slot. EVERY terminal
	// path must go through here rather than assigning BeepDialog{} directly —
	// see the definition for why (issue #148).
	void releaseDialog(BeepDialog& bd);
	// buildAck/buildBye take the dialog handleOk() already located — they used to
	// re-scan the table by Call-ID themselves, three linear passes over the same
	// Call-ID per answered beep, all inside the _mutex-held 200-OK dispatch.
	// for2xx: the ACK for a 2xx takes a fresh Via branch; a non-2xx ACK reuses the INVITE's (#752).
	std::shared_ptr<SipMessage> buildAck(const BeepDialog& bd, const std::shared_ptr<SipMessage>& ok, bool for2xx);
	std::shared_ptr<SipMessage> buildBye(const BeepDialog& bd, const std::shared_ptr<SipMessage>& ok);
	std::shared_ptr<SipMessage> buildCancel(std::size_t slot);

	// Issue #104: cap on consecutive buildCancel() retries (see BeepDialog::
	// cancelRetries) before sweep() gives up and frees the slot outright rather
	// than retrying forever under sustained message-pool pressure.
	static constexpr int kMaxCancelRetries = 5;

	// Bounded outbound-UAC dialog table. Tiny fixed footprint; if all slots are
	// busy a new registration just skips its beep.
	std::array<BeepDialog, POCKETDIAL_MAX_BEEPS> _dialogs;
	PbxEnv& _env;
};

#endif
