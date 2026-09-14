#ifndef SERVICE_EXTENSIONS_HPP
#define SERVICE_EXTENSIONS_HPP

// ServiceExtensions.hpp — the fixed table of SERVICE EXTENSIONS (Issue #202).
//
// A service extension is an alphanumeric pseudo-AOR the ENGINE owns rather than
// a phone: `pbx` (the register beep's From), `moh` (the hold-music preview's
// From), `server` (the server-initiated BYE's From). Those three identities
// already existed — as string literals in nine places across RegisterBeeper.cpp
// and RequestsHandler.cpp — with nothing in the system that knew they were
// names the PBX had claimed. This header is that somewhere: one place that
// says which names the engine owns, and what may be done with each.
//
// Why a table and not a naming convention. Issue #202 asks for three properties
// that a convention cannot give:
//
//   1. The names must be RESERVED. A dial-plan rule, a ring group, a DID map or
//      a call-forward target that happened to be spelled "pbx" would shadow an
//      identity the engine originates as — and the register-beep response path
//      depends, by name, on findClient("pbx") MISSING (see the comment at
//      RequestsHandler.cpp's onReqTerminated: a beep's From resolving to a real
//      client is what used to mint a stray 404 back at the phone). A table lets
//      every guard ask one question instead of each carrying its own literal.
//
//   2. They must not be REGISTERABLE. Not in _clientPool, so they cost no
//      registration capacity, never appear in the dashboard roster, and are not
//      adoptable in Learn mode. That is enforced by onRegister rejecting a
//      REGISTER whose From names a service, plus by the simple fact that these
//      records live in their own array.
//
//   3. DIALABILITY must be per-service, because it is not one answer. A future
//      `voicemail` must be dialable (that is how a subscriber checks messages);
//      a future `admin` must not. So it is a flag on the record.
//
// ── Why every seed below is dialable=false ────────────────────────────────────
//
// `dialable` gates whether RequestsHandler::findRegistered() — the single choke
// point every routing caller already goes through (CallForker's blind transfer
// / CFU / CFB / CFNA / ring groups, CallPickup, ParkOrbit, DtmfFeatureCodes) —
// will resolve the name to a callable peer. Issue #202 proposes resolving it to
// a LOOPBACK peer at the server's own address, so the INVITE comes back to us
// and onInvite intercepts it by name the way 440/555/777/888 already are.
//
// That round trip does NOT complete on this codebase today, for two independent
// reasons, so shipping a dialable service without its dispatch would be worse
// than the black hole it is meant to fix:
//
//   (a) CallForker::buildInviteFork clones the caller's INVITE verbatim — same
//       Call-ID, Via, From and CSeq — and every redirectInvite path has already
//       published a Session under that Call-ID before it sends. onInvite's
//       retransmission guard (RFC 3261 §17.2.3) sees a live session in state
//       Invited for that Call-ID and SILENTLY DROPS the packet. Nothing arrives.
//
//   (b) Even past that guard, the looped INVITE's getSource() is the server's
//       own address, so every response built as
//       `_outbox.emplace_back(data->getSource(), ...)` is addressed back to the
//       server instead of the phone.
//
// Both are consequences of the engine being a forwarding proxy rather than a
// B2BUA on the ordinary call path — a property RequestsHandler.cpp states
// explicitly in armSessionTimer's "This PBX does not re-originate calls on the
// ordinary call path" comment. Making the loopback work means minting a fresh
// Call-ID for the inner leg and correlating two dialogs, which is a deliberate
// architectural change and not this issue's scope.
//
// So: the LOOKUP is wired (findRegistered consults this table after the client
// pool misses), the FLAG is honoured, and the seeds are declared non-dialable
// until a dispatch mechanism exists to answer them. Flipping one to true is a
// one-word change once that lands — which is the point of putting the decision
// in a table.

#include <array>
#include <cstddef>
#include <string_view>

#include "PoolConfig.hpp"

namespace pbx
{
	struct ServiceEndpoint
	{
		// The pseudo-AOR. Must satisfy RequestsHandler::isValidAor, which already
		// admits std::isalnum plus . - _ + * # — so an alphanumeric name like
		// "voicemail" is legal on the wire today with no parser change.
		std::string_view name{};

		// May a call be ROUTED here? See the header comment: false for every seed
		// until the loopback dispatch exists. A false entry is still reserved
		// (nothing may be configured under its name) and still an identity the
		// engine originates as — it simply cannot be the target of a call.
		bool dialable = false;
	};

	// The identities the engine already originates as. Spelled once here and
	// referenced from the places that build the From/Contact headers.
	inline constexpr std::string_view kServicePbx    = "pbx";      // register beep
	inline constexpr std::string_view kServiceMoh    = "moh";      // hold-music preview
	inline constexpr std::string_view kServiceServer = "server";   // server-initiated BYE

	// How many entries of kServiceEndpoints are live. The array is sized by the
	// POCKETDIAL_MAX_SERVICES knob (PoolConfig.hpp) so the storage cost is fixed
	// at compile time with headroom for the services #194/#168 will add;
	// everything past this count is a default-constructed (empty-name) record
	// that the lookups below never read.
	inline constexpr std::size_t kServiceEndpointCount = 3;

	static_assert(kServiceEndpointCount <= static_cast<std::size_t>(POCKETDIAL_MAX_SERVICES),
		"POCKETDIAL_MAX_SERVICES is smaller than the number of seeded service "
		"extensions — raise the knob in PoolConfig.hpp");

	inline constexpr std::array<ServiceEndpoint, POCKETDIAL_MAX_SERVICES> kServiceEndpoints{{
		{ kServicePbx,    false },
		{ kServiceMoh,    false },
		{ kServiceServer, false },
		// Future (Issue #194 Stage 3 / #168), once a dispatch mechanism answers them:
		//   { "voicemail", true  },
		//   { "attendant", true  },
		//   { "admin",     false },
	}};

	// Index of `name` in the table, or -1. Returned as an index rather than a
	// pointer because the engine keeps a PARALLEL array of pre-allocated peer
	// objects and needs to address the same slot.
	inline int serviceEndpointIndex(std::string_view name)
	{
		// An empty name would otherwise match the unused tail of the array if the
		// bound below were ever widened; guard it here rather than relying on that.
		if (name.empty()) return -1;
		for (std::size_t i = 0; i < kServiceEndpointCount; ++i)
		{
			if (kServiceEndpoints[i].name == name) return static_cast<int>(i);
		}
		return -1;
	}

	inline const ServiceEndpoint* findServiceEndpoint(std::string_view name)
	{
		const int idx = serviceEndpointIndex(name);
		return idx < 0 ? nullptr : &kServiceEndpoints[static_cast<std::size_t>(idx)];
	}

	// Is this a name the engine has claimed? TRUE for non-dialable services too —
	// this is the question the reserved-name guards ask, and reserving the name is
	// exactly what a non-dialable service still needs.
	inline bool isServiceName(std::string_view name)
	{
		return serviceEndpointIndex(name) >= 0;
	}

	// May a call be routed to this name? The narrower question, asked only by
	// findRegistered(). Currently false for every seed — see the header comment.
	inline bool isDialableService(std::string_view name)
	{
		const ServiceEndpoint* s = findServiceEndpoint(name);
		return s != nullptr && s->dialable;
	}
}

#endif
