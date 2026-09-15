// PbxFeatureConfig.cpp: the five PBX feature tables (DND, forwards, ring
// groups, page zones, dial plan), extracted out of RequestsHandler.
#include "PbxFeatureConfig.hpp"

#include <algorithm>
#include <cstdlib>

#include "PbxPersist.hpp"
#include "ServiceExtensions.hpp"   // Issue #202: the engine-owned pseudo-AOR table

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
#include "nvs_flash.h"
#include "nvs.h"
#endif

namespace
{
	using pbxpersist::deserializeBlob;
}

// ── Do Not Disturb ──────────────────────────────────────────────────────────

void PbxFeatureConfig::setDndLocked(const std::string& extension, bool on)
{
	if (on)
	{
		// Bound the map so a flood of distinct extensions can't grow the heap
		// without limit. Mirror the client-pool cap; reject new keys past it.
		if (_dnd.find(extension) == _dnd.end() &&
			_dnd.size() >= static_cast<size_t>(POCKETDIAL_MAX_CLIENTS))
		{
			_env.log("DND set ignored (table full) for extension " + extension, true);
		}
		else
		{
			_dnd[extension] = true;
		}
	}
	else
	{
		// Turning DND off frees the slot, so the map only ever holds the
		// extensions that are actively in DND (bounded by registrations).
		_dnd.erase(extension);
	}
	_env.log("DND " + std::string(on ? "enabled" : "disabled") + " for extension " + extension);

	// Refresh the DND view in the dashboard snapshot immediately so the UI
	// reflects the change without waiting for the next tick(). Same refresh
	// regardless of whether the mutation came from the HTTP setter or a DTMF
	// CLASS code (Issue #77) — both funnel through here.
	_onChanged(Table::Dnd);
}

bool PbxFeatureConfig::isDndEnabled(const std::string& extension) const
{
	// Internal lookup: invoked from onInvite() which already holds _mutex, so this
	// must NOT take _mutex (std::mutex is non-recursive). Bounded map lookup.
	auto it = _dnd.find(extension);
	return it != _dnd.end() && it->second;
}

std::vector<std::string> PbxFeatureConfig::dndSnapshot() const
{
	std::vector<std::string> result;
	result.reserve(_dnd.size());
	for (const auto& [ext, enabled] : _dnd)
	{
		if (enabled) result.push_back(ext);
	}
	return result;
}

// ── Call forwarding (CFU/CFB/CFNA) ───────────────────────────────────────────

std::string PbxFeatureConfig::getForwardTarget(const std::string& extension, const std::string& trigger) const
{
	// Internal lookup invoked from onInvite()/onBusy()/tick(), all of which already
	// hold _mutex — must NOT lock (non-recursive). Bounded map lookup.
	auto it = _forwards.find(extension);
	if (it == _forwards.end())
	{
		return {};
	}
	if (trigger == "always")   return it->second.always;
	if (trigger == "busy")     return it->second.busy;
	if (trigger == "noanswer") return it->second.noAnswer;
	return {};
}

void PbxFeatureConfig::setForwardLocked(const std::string& extension, const std::string& trigger, const std::string& target)
{
	// Reject the virtual extensions outright; they are not real endpoints.
	// Previously only the HTTP-facing setForward() applied this guard — the
	// DTMF *73/*72NNNN inline path skipped it entirely (Issue #77), so a
	// crafted mid-dialog INFO with From: 777/999 could set up a "forward" on
	// a virtual extension. Routing both callers through here closes that gap.
	// "888" is ConferenceRoom::EXT (the meet-me conference), "555" is the anchor
	// media bridge (RequestsHandler.cpp's kAnchorCallExt) — neither referenced
	// by name here so this file stays decoupled from ConferenceRoom.hpp/RequestsHandler.hpp.
	// Issue #166: pbx::isReservedExtension() is the single list, so 440 and
	// the emergency numbers 911/933 are covered here too rather than only in
	// the REGISTER identity guard, which was the only caller it had.
	if (pbx::isReservedExtension(extension))
	{
		_env.log("Forward set ignored for virtual extension " + extension, true);
	}
	// Issue #202: the same refusal for a SERVICE extension (`pbx`/`moh`/`server`)
	// as the SUBSCRIBER. A service is an engine identity, never an endpoint with a
	// mailbox of its own to forward away from, and letting one be configured here
	// would put an engine-owned name into the persisted forward table.
	else if (pbx::isServiceName(extension))
	{
		_env.log("Forward set ignored for service extension " + extension, true);
	}
	// ...and, new, a guard on the TARGET — which nothing has ever validated. This
	// is narrow on purpose: it refuses ONLY a service name that is not dialable,
	// i.e. a target the engine knows by name and knows it cannot deliver to. A
	// forward pointed at one would be accepted, fire, and then black-hole the call
	// inside redirectInvite()'s findRegistered() miss. Refusing it at config time
	// is the difference between "the dashboard told me no" and "calls to that
	// extension silently stopped arriving". Unknown NON-service targets are
	// deliberately still accepted: an extension that is merely offline right now
	// must remain a legal forward target, and telling those two cases apart is
	// exactly what Issue #202's routing work is for.
	else if (!target.empty() && pbx::isServiceName(target) && !pbx::isDialableService(target))
	{
		_env.log("Forward set ignored: service extension " + target +
			" cannot receive calls", true);
	}
	else
	{
		auto it = _forwards.find(extension);
		bool isNew = (it == _forwards.end());

		// Bound the table like _dnd: refuse a brand-new extension past the cap.
		if (isNew && _forwards.size() >= static_cast<size_t>(POCKETDIAL_MAX_CLIENTS))
		{
			_env.log("Forward set ignored (table full) for extension " + extension, true);
		}
		else
		{
			pbx::ForwardConfig& cfg = _forwards[extension];
			if (trigger == "always")        cfg.always   = target;
			else if (trigger == "busy")     cfg.busy     = target;
			else if (trigger == "noanswer") cfg.noAnswer = target;

			// Drop the entry entirely once no trigger remains set, so the map only
			// holds actively-forwarded extensions (bounded by registrations).
			if (cfg.empty())
			{
				_forwards.erase(extension);
			}
			_env.log("Forward " + trigger + " for " + extension +
				(target.empty() ? " cleared" : (" -> " + target)));
			persistForwards();
		}
	}

	// Refresh the dashboard snapshot immediately (mirror setDnd). Same refresh
	// regardless of whether the mutation came from the HTTP setter or a DTMF
	// CLASS code (Issue #77) — both funnel through here.
	_onChanged(Table::Forwards);
}

std::vector<std::tuple<std::string, std::string, std::string, std::string>> PbxFeatureConfig::forwardsSnapshot() const
{
	std::vector<std::tuple<std::string, std::string, std::string, std::string>> result;
	result.reserve(_forwards.size());
	for (const auto& [ext, cfg] : _forwards)
	{
		result.emplace_back(ext, cfg.always, cfg.busy, cfg.noAnswer);
	}
	return result;
}

// ── Ring / hunt groups ───────────────────────────────────────────────────────

const pbx::RingGroup* PbxFeatureConfig::findRingGroup(const std::string& extension) const
{
	// Internal lookup from onInvite() (already holds _mutex). Bounded map lookup.
	auto it = _ringGroups.find(extension);
	return (it == _ringGroups.end()) ? nullptr : &it->second;
}

void PbxFeatureConfig::setRingGroup(const std::string& groupExt, const std::string& members, const std::string& mode)
{
	// One shared list (pbx::isReservedExtension) rather than a hand-copied one:
	// the three validators in this file had drifted into three DIFFERENT
	// lists, and none of them covered 911/933. A ring group named "911"
	// was accepted and persisted, and findRingGroup() runs before the dial
	// plan in onInvite() -- so it would have shadowed emergency dialing
	// outright had #166 not moved that check ahead of every lookup.
	if (pbx::isReservedExtension(groupExt))
	{
		_env.log("Ring group ignored for reserved extension " + groupExt, true);
	}
	// Issue #202: a group named for a service extension would SHADOW that name —
	// onInvite resolves ring groups before the extension lookup, so whatever the
	// engine later wanted `pbx`/`moh` to mean would never be reached. Refuse it
	// here rather than let the shadow be persisted to NVS.
	else if (pbx::isServiceName(groupExt))
	{
		_env.log("Ring group ignored for service extension " + groupExt, true);
	}
	else
	{
		std::vector<std::string> list = pbx::splitMembers(members);
		if (list.empty())
		{
			// Empty membership deletes the group.
			_ringGroups.erase(groupExt);
			_env.log("Ring group " + groupExt + " deleted");
			persistRingGroups();
		}
		else
		{
			bool isNew = (_ringGroups.find(groupExt) == _ringGroups.end());
			if (isNew && _ringGroups.size() >= static_cast<size_t>(POCKETDIAL_MAX_CLIENTS))
			{
				_env.log("Ring group ignored (table full) for " + groupExt, true);
			}
			else
			{
				pbx::RingGroup& g = _ringGroups[groupExt];
				g.members = std::move(list);
				g.mode = (mode == "hunt") ? pbx::GroupMode::Hunt : pbx::GroupMode::RingAll;
				_env.log("Ring group " + groupExt + " (" +
					(g.mode == pbx::GroupMode::Hunt ? "hunt" : "ringall") + ") = " +
					pbx::joinMembers(g.members));
				persistRingGroups();
			}
		}
	}

	// Refresh dashboard snapshot immediately.
	_onChanged(Table::RingGroups);
}

std::vector<std::tuple<std::string, std::string, std::string>> PbxFeatureConfig::ringGroupsSnapshot() const
{
	std::vector<std::tuple<std::string, std::string, std::string>> result;
	result.reserve(_ringGroups.size());
	for (const auto& [ext, g] : _ringGroups)
	{
		result.emplace_back(ext,
			g.mode == pbx::GroupMode::Hunt ? "hunt" : "ringall",
			pbx::joinMembers(g.members));
	}
	return result;
}

// ── Paging zones (980–989) ────────────────────────────────────────────────────

const pbx::PageZone* PbxFeatureConfig::findPageZone(const std::string& extension) const
{
	auto it = _pageZones.find(extension);
	return (it == _pageZones.end()) ? nullptr : &it->second;
}

bool PbxFeatureConfig::isPageZoneDialog(const std::string& extension) const
{
	return pbx::isPageZoneExt(extension) && _pageZones.find(extension) != _pageZones.end();
}

void PbxFeatureConfig::setPageZone(const std::string& zoneExt, const std::string& members)
{
	if (!pbx::isPageZoneExt(zoneExt))
	{
		_env.log("Page zone ignored for non-zone extension " + zoneExt +
			" (zones are 980-989)", true);
	}
	else
	{
		std::vector<std::string> list = pbx::splitZoneMembers(members);
		if (list.empty())
		{
			_pageZones.erase(zoneExt);
			_env.log("Page zone " + zoneExt + " deleted");
			persistPageZones();
		}
		else
		{
			bool isNew = (_pageZones.find(zoneExt) == _pageZones.end());
			if (isNew && _pageZones.size() >= static_cast<size_t>(POCKETDIAL_MAX_PAGE_ZONES))
			{
				_env.log("Page zone ignored (table full) for " + zoneExt, true);
			}
			else
			{
				pbx::PageZone& z = _pageZones[zoneExt];
				z.members = std::move(list);
				_env.log("Page zone " + zoneExt + " = " + pbx::joinMembers(z.members));
				persistPageZones();
			}
		}
	}

	_onChanged(Table::PageZones);
}

std::vector<std::pair<std::string, std::string>> PbxFeatureConfig::pageZonesSnapshot() const
{
	std::vector<std::pair<std::string, std::string>> result;
	result.reserve(_pageZones.size());
	for (const auto& [ext, z] : _pageZones)
	{
		result.emplace_back(ext, pbx::joinMembers(z.members));
	}
	return result;
}

// ── Dial plan (Issue #69) ─────────────────────────────────────────────────────

void PbxFeatureConfig::setDialRule(const std::string& pattern, const std::string& action,
	const std::string& target, int stripDigits)
{
	// Validate once, here, so a bad rule can never reach the SIP thread — and
	// so the NVS blob (tab/newline delimited) can never be corrupted by a
	// smuggled separator. Same "log and drop" contract as setRingGroup.
	if (!pbx::isDialTokenSafe(pattern))
	{
		_env.log("Dial rule ignored: invalid pattern \"" + pattern + "\"", true);
	}
	else if (pbx::isReservedExtension(pattern))
	{
		// These are handled above the dial plan in onInvite(), so a rule here
		// would never fire. Refuse it instead of accepting a dead rule.
		_env.log("Dial rule ignored: " + pattern +
			" is a reserved extension and is routed before the dial plan", true);
	}
	// Issue #202: the dial plan is where a catch-all pattern lives (#201's SBC
	// mode), so it is also where a service name is most easily swallowed. Refuse
	// an exact service-name pattern for the same reason as the numeric reserved
	// extensions above — the name belongs to the engine.
	else if (pbx::isServiceName(pattern))
	{
		_env.log("Dial rule ignored: " + pattern +
			" is a reserved service extension", true);
	}
	else if (action.empty() && target.empty())
	{
		// Deleting takes an empty ACTION as well as an empty target (mirrors
		// setRingGroup's empty member list). Keying the delete on the target
		// alone made "strip N and prepend nothing" — drawbridge's only trunk
		// shape — impossible to express, because the request that would create
		// it is byte-identical to the request that deletes it. Naming an action
		// now always means "upsert".
		if (_dialPlan.erase(pattern))
		{
			_env.log("Dial rule " + pattern + " deleted");
			persistDialPlan();
		}
	}
	else if (!target.empty() && !pbx::isDialTokenSafe(target))
	{
		_env.log("Dial rule ignored: invalid target \"" + target + "\"", true);
	}
	else
	{
		pbx::DialActionType parsed;
		if (!pbx::parseDialAction(action, parsed))
		{
			_env.log("Dial rule ignored: unknown action \"" + action +
				"\" (want group|page|park|trunk)", true);
		}
		else if (target.empty() && parsed != pbx::DialActionType::Trunk)
		{
			// Only a trunk rule has a meaningful empty target ("prepend nothing").
			// A group/page/park rule with no target names no destination at all.
			_env.log("Dial rule ignored: " + action + " needs a target (only a trunk "
				"rule may leave it empty, meaning prepend nothing)", true);
		}
		else if (parsed == pbx::DialActionType::PageZone && !pbx::isPageZoneExt(target))
		{
			_env.log("Dial rule ignored: page target " + target +
				" is not a paging zone (zones are 980-989)", true);
		}
		else if (parsed == pbx::DialActionType::ParkOrbit && !pbx::isParkOrbitExt(target))
		{
			_env.log("Dial rule ignored: park target " + target +
				" is not a park orbit for this build", true);
		}
		else if (parsed == pbx::DialActionType::Trunk && stripDigits < 0)
		{
			_env.log("Dial rule ignored: trunk stripDigits must not be negative for " + pattern, true);
		}
		else if (parsed == pbx::DialActionType::Trunk && pattern.back() != '*' &&
			static_cast<size_t>(stripDigits) > pattern.size())
		{
			// Non-prefix pattern: every dialed string matching it is exactly
			// pattern.size() long, so a strip count longer than that can never
			// succeed — reject now rather than storing a rule that always 404s
			// (applyTrunkTransform() re-checks against the ACTUAL dialed string at
			// match time, which is the only possible check for a prefix pattern).
			_env.log("Dial rule ignored: trunk stripDigits " + std::to_string(stripDigits) +
				" exceeds pattern \"" + pattern + "\"'s fixed length", true);
		}
		else
		{
			pbx::DialRule rule;
			rule.pattern = pattern;
			rule.action = parsed;
			rule.target = target;
			rule.stripDigits = (parsed == pbx::DialActionType::Trunk) ? stripDigits : 0;
			if (!_dialPlan.upsert(rule))
			{
				_env.log("Dial rule ignored (table full) for " + pattern, true);
			}
			else
			{
				_env.log("Dial rule " + pattern + " -> " +
					pbx::dialActionName(parsed) + " " + target +
					(parsed == pbx::DialActionType::Trunk
						? " (strip " + std::to_string(rule.stripDigits) + ")" : ""));
				persistDialPlan();
			}
		}
	}

	// Refresh dashboard snapshot immediately (mirrors setRingGroup).
	_onChanged(Table::DialRules);
}

std::vector<std::tuple<std::string, std::string, std::string, int>> PbxFeatureConfig::dialRulesSnapshot() const
{
	std::vector<std::tuple<std::string, std::string, std::string, int>> result;
	result.reserve(_dialPlan.size());
	for (const auto& r : _dialPlan.rules())
	{
		result.emplace_back(r.pattern, pbx::dialActionName(r.action), r.target, r.stripDigits);
	}
	return result;
}

// ── Directed / group call pickup (Issue #68) ──────────────────────────────────
// See PbxConfig.hpp's isGroupPickupCode/directedPickupTarget doc comment: pickup
// groups are ring-group membership, reused as-is.

std::vector<std::string> PbxFeatureConfig::pickupPeersOf(const std::string& ext) const
{
	std::vector<std::string> peers;
	for (const auto& [groupExt, group] : _ringGroups)
	{
		bool isMember = false;
		for (const auto& m : group.members)
		{
			if (m == ext) { isMember = true; break; }
		}
		if (!isMember) continue;

		for (const auto& m : group.members)
		{
			if (m == ext) continue;
			if (std::find(peers.begin(), peers.end(), m) == peers.end())
			{
				peers.push_back(m);
			}
		}
	}
	return peers;
}

// ── NVS persistence ────────────────────────────────────────────────────────
//
// All five helpers are no-ops on host (the in-memory maps/ring ARE the store) and
// gate their NVS access on ESP_PLATFORM. Each table is serialized as a single blob
// (one record per line; fields tab-separated) under one NVS key, so a mutation
// rewrites exactly one key — bounded size, low flash wear. Records are bounded by
// POCKETDIAL_MAX_CLIENTS / POCKETDIAL_MAX_PAGE_ZONES, so the blob can never grow
// without limit. The AOR charset (isValidAor) excludes tab/newline, so the
// delimiters are safe. Callers hold _mutex (except construction-time loads, which
// run single-threaded before any handler dispatches).

void PbxFeatureConfig::loadPbxConfig()
{
	if (_pbxConfigLoaded)
	{
		return;
	}
	_pbxConfigLoaded = true;

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	nvs_handle_t h;
	if (nvs_open(pbxpersist::kNvsNamespace, NVS_READWRITE, &h) != ESP_OK)
	{
		return;
	}

	auto readBlob = [&](const char* key) -> std::string {
		size_t len = 0;
		if (nvs_get_str(h, key, nullptr, &len) != ESP_OK || len == 0)
		{
			return {};
		}
		std::string buf(len, '\0');
		if (nvs_get_str(h, key, buf.data(), &len) != ESP_OK)
		{
			return {};
		}
		if (!buf.empty() && buf.back() == '\0') buf.pop_back(); // drop NUL terminator
		return buf;
	};

	// Forwards: ext \t always \t busy \t noAnswer
	for (const auto& rec : deserializeBlob(readBlob("forwards")))
	{
		if (rec.size() < 4 || rec[0].empty()) continue;
		if (_forwards.size() >= static_cast<size_t>(POCKETDIAL_MAX_CLIENTS)) break;
		pbx::ForwardConfig cfg;
		cfg.always = rec[1];
		cfg.busy = rec[2];
		cfg.noAnswer = rec[3];
		if (!cfg.empty()) _forwards[rec[0]] = std::move(cfg);
	}

	// Ring groups: ext \t mode \t m1,m2,...
	for (const auto& rec : deserializeBlob(readBlob("groups")))
	{
		if (rec.size() < 3 || rec[0].empty()) continue;
		if (_ringGroups.size() >= static_cast<size_t>(POCKETDIAL_MAX_CLIENTS)) break;
		pbx::RingGroup g;
		g.mode = (rec[1] == "hunt") ? pbx::GroupMode::Hunt : pbx::GroupMode::RingAll;
		g.members = pbx::splitMembers(rec[2]);
		if (!g.members.empty()) _ringGroups[rec[0]] = std::move(g);
	}

	// Page zones: ext \t m1,m2,...
	for (const auto& rec : deserializeBlob(readBlob("pzones")))
	{
		if (rec.size() < 2 || rec[0].empty()) continue;
		if (_pageZones.size() >= static_cast<size_t>(POCKETDIAL_MAX_PAGE_ZONES)) break;
		pbx::PageZone z;
		z.members = pbx::splitZoneMembers(rec[1]);
		if (!z.members.empty()) _pageZones[rec[0]] = std::move(z);
	}

	// Dial plan (Issue #69): pattern \t action \t target [\t stripDigits], one
	// record per rule, in evaluation order. The 4th field (Issue #165's Trunk
	// action) is optional so a blob written before it existed still loads: a
	// record with exactly 3 fields gets stripDigits 0, same as any non-trunk
	// rule. DialPlan::upsert() enforces POCKETDIAL_MAX_DIAL_RULES on its own, so
	// a blob written by a build with a larger cap simply stops being applied at
	// this build's ceiling instead of overflowing it. Records that no longer
	// validate (an unknown action, a park target outside a shrunken
	// POCKETDIAL_PARK_SLOTS, or a strip count now impossible for its pattern)
	// are dropped rather than loaded.
	for (const auto& rec : deserializeBlob(readBlob("dplan")))
	{
		if (rec.size() < 3 || rec[0].empty() || rec[2].empty()) continue;
		pbx::DialRule rule;
		if (!pbx::parseDialAction(rec[1], rule.action)) continue;
		if (!pbx::isDialTokenSafe(rec[0]) || !pbx::isDialTokenSafe(rec[2])) continue;
		if (rule.action == pbx::DialActionType::PageZone && !pbx::isPageZoneExt(rec[2])) continue;
		if (rule.action == pbx::DialActionType::ParkOrbit && !pbx::isParkOrbitExt(rec[2])) continue;
		int stripDigits = 0;
		if (rule.action == pbx::DialActionType::Trunk && rec.size() >= 4 && !rec[3].empty())
		{
			stripDigits = std::atoi(rec[3].c_str());
		}
		if (rule.action == pbx::DialActionType::Trunk &&
			(stripDigits < 0 || (rec[0].back() != '*' && static_cast<size_t>(stripDigits) > rec[0].size())))
		{
			continue;
		}
		rule.pattern = rec[0];
		rule.target = rec[2];
		rule.stripDigits = (rule.action == pbx::DialActionType::Trunk) ? stripDigits : 0;
		if (!_dialPlan.upsert(rule)) break;   // table full at this build's cap
	}

	nvs_close(h);
#endif
}

void PbxFeatureConfig::persistForwards()
{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	std::string blob;
	for (const auto& [ext, cfg] : _forwards)
	{
		blob += ext; blob += '\t';
		blob += cfg.always; blob += '\t';
		blob += cfg.busy; blob += '\t';
		blob += cfg.noAnswer; blob += '\n';
	}
	nvs_handle_t h;
	if (nvs_open(pbxpersist::kNvsNamespace, NVS_READWRITE, &h) == ESP_OK)
	{
		nvs_set_str(h, "forwards", blob.c_str());
		nvs_commit(h);
		nvs_close(h);
	}
#endif
}

void PbxFeatureConfig::persistRingGroups()
{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	std::string blob;
	for (const auto& [ext, g] : _ringGroups)
	{
		blob += ext; blob += '\t';
		blob += (g.mode == pbx::GroupMode::Hunt ? "hunt" : "ringall"); blob += '\t';
		blob += pbx::joinMembers(g.members); blob += '\n';
	}
	nvs_handle_t h;
	if (nvs_open(pbxpersist::kNvsNamespace, NVS_READWRITE, &h) == ESP_OK)
	{
		nvs_set_str(h, "groups", blob.c_str());
		nvs_commit(h);
		nvs_close(h);
	}
#endif
}

void PbxFeatureConfig::persistPageZones()
{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	std::string blob;
	for (const auto& [ext, z] : _pageZones)
	{
		blob += ext; blob += '\t';
		blob += pbx::joinMembers(z.members); blob += '\n';
	}
	nvs_handle_t h;
	if (nvs_open(pbxpersist::kNvsNamespace, NVS_READWRITE, &h) == ESP_OK)
	{
		nvs_set_str(h, "pzones", blob.c_str());
		nvs_commit(h);
		nvs_close(h);
	}
#endif
}

void PbxFeatureConfig::persistDialPlan()
{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	// Order matters here in a way it does not for the maps above: the blob is
	// written (and replayed) in table order, because that IS the evaluation order.
	std::string blob;
	for (const auto& r : _dialPlan.rules())
	{
		blob += r.pattern; blob += '\t';
		blob += pbx::dialActionName(r.action); blob += '\t';
		blob += r.target; blob += '\t';
		blob += std::to_string(r.stripDigits); blob += '\n';
	}
	nvs_handle_t h;
	if (nvs_open(pbxpersist::kNvsNamespace, NVS_READWRITE, &h) == ESP_OK)
	{
		nvs_set_str(h, "dplan", blob.c_str());
		nvs_commit(h);
		nvs_close(h);
	}
#endif
}
