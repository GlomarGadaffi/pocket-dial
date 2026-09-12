#ifndef REGISTER_BEEPER_HPP
#define REGISTER_BEEPER_HPP

#include <array>
#include <chrono>
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
//                            with no further response — the dialog's own 487, if
//                            the CANCEL landed in time, is routed to
//                            RequestsHandler::onReqTerminated, which has no
//                            Session to key a beep dialog off; this fallback is
//                            what actually frees the slot in that case).
//
// Locking: every method assumes the caller holds the engine's _mutex
// (non-recursive), matching the RequestsHandler code this was extracted from.
class RegisterBeeper
{
public:
	explicit RegisterBeeper(PbxEnv& env) : _env(env) {}

	// Kick off a beep dialog toward a freshly registered phone. Bounded and
	// best-effort — if the table is full the beep is simply skipped.
	void sendBeep(const std::shared_ptr<SipClient>& phone);

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

	// Time out overdue dialogs: CANCEL an unanswered INVITE (see sweep()'s own
	// comment for why the slot isn't freed immediately), free a slot whose
	// bounded fallback window has expired either way.
	void sweep(std::chrono::steady_clock::time_point now);

private:
	// AwaitingCancelDone: CANCEL sent for an unanswered INVITE, lingering for a
	// bounded window in case the phone's 200 OK raced the CANCEL (RFC 3261 §9.1) —
	// handleOk() still matches this state so a raced answer gets ACKed+BYEd.
	enum class BeepState { Free, AwaitingInviteOk, AwaitingByeOk, AwaitingCancelDone };
	struct BeepDialog
	{
		BeepState state = BeepState::Free;
		std::string callID;        // fresh per beep; how handleOk()/sweep() find this slot
		std::string branch;        // Via branch (reused for INVITE/CANCEL)
		std::string fromTag;       // our (server) From tag
		std::string ext;           // target extension (phone number)
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
	// buildAck/buildBye take the dialog handleOk() already located — they used to
	// re-scan the table by Call-ID themselves, three linear passes over the same
	// Call-ID per answered beep, all inside the _mutex-held 200-OK dispatch.
	std::shared_ptr<SipMessage> buildAck(const BeepDialog& bd, const std::shared_ptr<SipMessage>& ok);
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
