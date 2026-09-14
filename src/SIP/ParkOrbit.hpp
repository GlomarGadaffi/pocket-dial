#ifndef PARK_ORBIT_HPP
#define PARK_ORBIT_HPP

#include <array>
#include <chrono>
#include <memory>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

#include "PbxEnv.hpp"
#include "PoolConfig.hpp"
#include "SipClient.hpp"
#include "HoldMusic.hpp"
#include "SipMessage.hpp"

// ── Call parking / park-orbit state machine ───────────────────────────────────
// Virtual orbit extensions 700..70(N-1). An INVITE to a FREE orbit parks the
// caller's leg there; an INVITE to an OCCUPIED orbit retrieves it: the
// retriever is answered with the parked party's SDP and the parked party is
// re-INVITEd so media renegotiates peer-to-peer. sweep() handles timed-out
// parks: ring back the parker (when registered), else tear down with BYE.
//
// Locking: every method assumes the caller holds the engine's _mutex and only
// enqueues to the outbox via PbxEnv — same convention as the RequestsHandler
// monolith this was extracted from.
class ParkOrbit
{
public:
	explicit ParkOrbit(PbxEnv& env) : _env(env) {}

	// Music on hold (issue #162). Optional by design: with no HoldMusic attached,
	// or with one that has no clip loaded, park answers exactly as it always did —
	// `a=inactive` on port 9, and the caller hears silence. A missing or unreadable
	// clip must never cost anyone the ability to park a call, so every failure path
	// below degrades to that instead of refusing the park.
	void setHoldMusic(HoldMusic* moh) { _moh = moh; }

	// Map "700".."709" to an orbit index, or -1 for anything else.
	int orbitIndex(std::string_view ext) const;

	// INVITE aimed at an orbit: park (free slot) or retrieve (occupied slot).
	void onInvite(const std::shared_ptr<SipMessage>& data,
		const std::shared_ptr<SipClient>& caller, int orbitIdx);

	// Route a 200 OK belonging to a park dialog (re-INVITE ACKs + ring-back
	// answers). Returns true if the response was consumed.
	bool handleOk(const std::shared_ptr<SipMessage>& data);

	// Time out overdue parks (ring back the parker or tear down) and expired
	// ring-backs.
	void sweep(std::chrono::steady_clock::time_point now);

	// Free any orbit slot holding this call's parked leg (call teardown path).
	void freeForCallId(std::string_view callID);

	// Rows for the dashboard snapshot: {orbit, parkedExt, parker, secondsParked}.
	// `onlyParked` limits to slots in the Parked state (the tick() full-snapshot
	// view); otherwise every occupied slot is listed (the park-op refresh view).
	std::vector<std::tuple<std::string, std::string, std::string, int>>
	snapshotRows(std::chrono::steady_clock::time_point now, bool onlyParked) const;

	// True (and resets the flag) if an orbit slot changed since the last call —
	// the cue to re-mirror snapshotRows() into the dashboard snapshot. Same
	// contract as Registrar::consumeDevicesChange(), and polled from the same
	// once-per-packet spot, so mirroring is no longer a duty each mutating call
	// site has to remember: sweep() and freeForCallId() self-signal too.
	bool consumeParkChanged();

private:
	enum class ParkState : uint8_t { Free, Parked, RingingBack, Retrieving };
	struct ParkSlot
	{
		ParkState state = ParkState::Free;
		std::string orbit;              // "700".."70N"
		std::string callID;             // Call-ID of the parked dialog
		std::string parkedExt;          // the parked party's extension
		sockaddr_in parkedAddr{};       // the parked party's signaling address
		bool        parked = false;     // slot has a captured parked dialog
		std::string parkedSdp;          // parked party's SDP (for retrieve / ring-back offers)
		std::string parkedFromTag;      // parked party's From-tag (re-INVITE / BYE To-tag)
		std::string localTag;           // our UAS To-tag on the parked dialog
		std::string parker;             // ring-back target on timeout
		std::chrono::steady_clock::time_point parkedAt{};
		// Ring-back UAC dialog toward the parker (server-minted, fresh Call-ID).
		std::string rbCallID;
		std::string rbFromTag;
		std::string rbBranch;
		sockaddr_in rbAddr{};
		std::chrono::steady_clock::time_point deadline{};
		// Music-on-hold listener id for this parked leg, or -1 when the slot has no
		// audio (no clip loaded, MoH failed to start, or the parked party's SDP
		// carried no usable RTP endpoint). -1 is the old silent-hold behaviour and
		// must stay a working state: a missing clip may not cost anyone a park.
		int mohListener = -1;
	};

	void sendReinvite(ParkSlot& slot, const std::string& sdp);
	void byeParkedParty(const ParkSlot& slot);
	void startRingback(ParkSlot& slot, const std::shared_ptr<SipClient>& parker,
		std::chrono::steady_clock::time_point now);

	// Release a slot back to Free and flag the dashboard mirror as stale. Every
	// path that clears a slot goes through here so none can forget to signal.
	void releaseSlot(ParkSlot& slot);

	std::array<ParkSlot, POCKETDIAL_PARK_SLOTS> _slots;
	std::chrono::seconds _timeout{POCKETDIAL_PARK_TIMEOUT_SEC};
	std::vector<std::string> _pendingAcks;   // park re-INVITE ACKs pending
	bool _parkChanged = false;               // slot state moved since the last mirror
	PbxEnv& _env;
	// Not owned. RequestsHandler holds the HoldMusic and attaches it at boot; null
	// means silent hold, which is the pre-#162 behaviour and a valid steady state.
	HoldMusic* _moh = nullptr;
};

#endif
