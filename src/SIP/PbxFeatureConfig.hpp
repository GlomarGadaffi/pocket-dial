#ifndef PBX_FEATURE_CONFIG_HPP
#define PBX_FEATURE_CONFIG_HPP

#include <functional>
#include <string>
#include <tuple>
#include <unordered_map>
#include <utility>
#include <vector>

#include "PbxConfig.hpp"
#include "DialPlan.hpp"
#include "PbxEnv.hpp"

// Owns the five bounded, NVS-persisted PBX feature tables that used to live
// directly on RequestsHandler: DND flags, call-forward config, ring/hunt
// groups, paging zones, and the dial plan rule table. Every method here
// assumes the caller already holds RequestsHandler's _mutex — same
// caller-holds-lock convention as the other decomposed machines
// (TransactionLayer, Registrar, ...). This one is reached through a plain
// `PbxEnv&` reference (for logging only, via the existing PbxEnv::log()) plus
// a narrow `OnChanged` callback, rather than the full PbxEnv surface: it needs
// no message pool, no sessions, no outbox — just data, validation, and NVS.
//
// The OnChanged callback exists because three of these setters (setRingGroup,
// setPageZone, setDialRule) and the two "Locked" DND/forward mutators refresh
// RequestsHandler's dashboard snapshot IMMEDIATELY on every mutation (Issue
// #77) — including from RequestsHandler::onDtmfInfo, which calls
// setDndLocked()/setForwardLocked() directly while already holding _mutex, not
// through the public HTTP-facing setters. That immediate-refresh contract has
// to survive the move, and RequestsHandler owns the snapshot/_snapshotMutex
// (per the decomposition's rule that snapshot mirroring stays in the engine),
// so this class can only ASK the engine to refresh, not do it directly.
class PbxFeatureConfig
{
public:
	// Which table changed, for the OnChanged callback -> RequestsHandler's
	// refreshPbxConfigSnapshot(Table) switch.
	enum class Table { Dnd, Forwards, RingGroups, PageZones, DialRules };
	using OnChanged = std::function<void(Table)>;

	PbxFeatureConfig(PbxEnv& env, OnChanged onChanged)
		: _env(env), _onChanged(std::move(onChanged)) {}

	// ── Do Not Disturb ────────────────────────────────────────────────────────
	// Lock-already-held mutation core (Issue #77): shared by the public
	// RequestsHandler::setDnd() (after it takes _mutex) and
	// RequestsHandler::onDtmfInfo()'s *60/*80 CLASS codes (already inside
	// _mutex via handle()), so both paths refresh the dashboard snapshot the
	// same way instead of onDtmfInfo leaving it stale.
	void setDndLocked(const std::string& extension, bool on);
	// Internal lookup used by onInvite(). Caller MUST already hold _mutex —
	// bounded map lookup, no locking of its own.
	bool isDndEnabled(const std::string& extension) const;
	// Snapshot-shaped view (extensions currently in DND) for
	// RequestsHandler::refreshPbxConfigSnapshot() and tick()'s periodic full
	// rebuild. Caller holds _mutex — this performs no locking of its own.
	std::vector<std::string> dndSnapshot() const;

	// ── Call forwarding (CFU/CFB/CFNA) ───────────────────────────────────────
	// Internal lookup used by onInvite()/onBusy()/tick(). Caller MUST already
	// hold _mutex. Returns "" when no forward of that trigger is configured.
	std::string getForwardTarget(const std::string& extension, const std::string& trigger) const;
	// Lock-already-held mutation core (Issue #77), same sharing rationale as
	// setDndLocked above (onDtmfInfo's *73/*72NNNN CLASS codes).
	void setForwardLocked(const std::string& extension, const std::string& trigger, const std::string& target);
	std::vector<std::tuple<std::string, std::string, std::string, std::string>> forwardsSnapshot() const;

	// ── Ring / hunt groups ────────────────────────────────────────────────────
	// Internal lookup from onInvite(). Caller MUST already hold _mutex.
	const pbx::RingGroup* findRingGroup(const std::string& extension) const;
	// Full validate + mutate + persist + snapshot-refresh, called from
	// RequestsHandler::setRingGroup() after it takes _mutex.
	void setRingGroup(const std::string& groupExt, const std::string& members, const std::string& mode);
	std::vector<std::tuple<std::string, std::string, std::string>> ringGroupsSnapshot() const;

	// ── Paging zones (980–989) ────────────────────────────────────────────────
	const pbx::PageZone* findPageZone(const std::string& extension) const;
	bool isPageZoneDialog(const std::string& extension) const;
	void setPageZone(const std::string& zoneExt, const std::string& members);
	std::vector<std::pair<std::string, std::string>> pageZonesSnapshot() const;

	// ── Dial plan (Issue #69, Trunk action Issue #165) ───────────────────────────
	// stripDigits is only meaningful for action "trunk" (leading digits removed
	// from the dialed string before prepending `target`); every other action
	// ignores it and it is stored as 0.
	void setDialRule(const std::string& pattern, const std::string& action, const std::string& target,
		int stripDigits = 0);
	std::vector<std::tuple<std::string, std::string, std::string, int>> dialRulesSnapshot() const;
	// Read-only access for CallForker::routeDialPlan() (CallForker.hpp) to call
	// .empty()/.match() on directly.
	const pbx::DialPlan& dialPlan() const { return _dialPlan; }

	// ── Directed / group call pickup (Issue #68) ──────────────────────────────
	// Every OTHER extension co-membered with `ext` in any configured ring
	// group, deduped and order-preserving. Empty if `ext` is in no group. Pure
	// membership query over _ringGroups — the rest of pickup (session-ringing
	// lookups) stays with RequestsHandler until the pickup/INVITE-dispatch
	// extraction. Caller holds _mutex.
	std::vector<std::string> pickupPeersOf(const std::string& ext) const;

	// Boot-time reload of all five tables from NVS. No-op on host (the maps are
	// the store). Construction is single-threaded (no handler is dispatching
	// yet), so this needs no lock; called once from RequestsHandler's
	// constructor, guarded by _pbxConfigLoaded against being re-run.
	void loadPbxConfig();

private:
	void persistForwards();
	void persistRingGroups();
	void persistPageZones();
	void persistDialPlan();

	PbxEnv& _env;
	OnChanged _onChanged;

	// DND state, keyed by extension. Bounded by the client-pool depth: an entry
	// is only created when DND is turned ON, and turning it OFF erases the
	// entry, so the map can never hold more than POCKETDIAL_MAX_CLIENTS live
	// extensions. (A std::shared_ptr<SipClient> flag would be lost across
	// re-REGISTER / pool eviction; keying by extension keeps DND sticky.)
	std::unordered_map<std::string, bool> _dnd;

	// Call-forwarding config, keyed by extension (Class A sweep). Same
	// bounding/stickiness rationale as _dnd: an entry exists only while at
	// least one trigger is set, and is bounded by POCKETDIAL_MAX_CLIENTS.
	std::unordered_map<std::string, pbx::ForwardConfig> _forwards;

	// Ring/hunt groups, keyed by the group extension (e.g. 6xx). Bounded by
	// POCKETDIAL_MAX_CLIENTS groups; each member list is bounded by
	// splitMembers().
	std::unordered_map<std::string, pbx::RingGroup> _ringGroups;

	// Paging zones, keyed by the zone extension (980–989). Bounded by
	// POCKETDIAL_MAX_PAGE_ZONES; member lists bounded by splitZoneMembers().
	std::unordered_map<std::string, pbx::PageZone> _pageZones;

	// Dial-plan rule table (Issue #69). An ORDERED vector, not a map: first
	// match wins, so evaluation order is the semantics. Hard-capped at
	// POCKETDIAL_MAX_DIAL_RULES by DialPlan::upsert(). Empty by default, and an
	// empty table is a no-op on routing.
	pbx::DialPlan _dialPlan;

	bool _pbxConfigLoaded = false;
};

#endif
