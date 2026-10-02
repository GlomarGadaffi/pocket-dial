#include "Registrar.hpp"
#include "SipWireUtil.hpp"

#include <algorithm>
#include <cstdlib>
#include <cstring>

#include "ArpLookup.hpp"
#include "DeviceConfig.hpp"   // Issue #397: lastSchemaOutcome() decides the boot default
#include "IDGen.hpp"
#include "PbxPersist.hpp"
#include "PoolConfig.hpp"
#include "SipDigest.hpp"
#include "SipSecretStore.hpp"

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	#include "nvs_flash.h"
	#include "nvs.h"
#endif

// ── Mode ──────────────────────────────────────────────────────────────────────

void Registrar::setMode(Mode mode)
{
	_mode.store(mode, std::memory_order_relaxed);
	persistMode();
	const char* name = (mode == Mode::Learn) ? "learn" : "secure";
	_env.log(std::string("Registrar mode set to ") + name);
}

Registrar::BootModeDecision Registrar::chooseBootMode(bool haveStored, Mode stored, BootSchema schema)
{
	// A missing key is what every failure looks like -- a persist that failed on
	// a fresh board, a factory reset whose write failed, an unreadable store --
	// so it means Learn (#441 review). There is no permissive mode left to fall
	// into: open is retired (#500), and a stored retired-open byte reaches here
	// already decoded as Learn (decodeStored).
	if (haveStored) return {stored, false};
	// Learn admits every first REGISTER, so phones keep working, then MAC-locks
	// each extension. Persist only when the store is trusted; an uncertain one is
	// re-decided on the next boot.
	return {Mode::Learn, schema != BootSchema::Uncertain};
}

void Registrar::loadMode()
{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	// Issue #397: the compiled-in seed used to be Open unconditionally, so every
	// board out of the box ran an open registrar. Now a board with no stored
	// mode gets one decided by chooseBootMode() from #181's schema outcome, which
	// app_main computes (DeviceConfig::ensureSchemaVersion) before the SIP task
	// constructs this object.
	nvs_handle_t h;
	const esp_err_t openErr = nvs_open(pbxpersist::kNvsNamespace, NVS_READWRITE, &h);
	if (openErr != ESP_OK)
	{
		// #441 review: this used to return and keep the constructor's Open seed,
		// so an unreadable store booted an open registrar. Learn, not persisted.
		_mode.store(Mode::Learn, std::memory_order_relaxed);
		_env.log(std::string("Registrar: cannot open NVS to read reg_mode (") + esp_err_to_name(openErr) +
			"); booting learn, not saved (#441)", true);
		return;
	}
	uint8_t v = 0;
	const esp_err_t err = nvs_get_u8(h, "reg_mode", &v);
	nvs_close(h);
	const StoredMode stored = (err == ESP_OK) ? decodeStored(v) : StoredMode{false, Mode::Learn, false};
	const bool haveStored = stored.valid;
	if (err != ESP_OK && err != ESP_ERR_NVS_NOT_FOUND)
	{
		_env.log(std::string("Registrar: reading reg_mode failed (") + esp_err_to_name(err) + ")", true);
	}

	BootSchema schema = BootSchema::Uncertain;
	switch (DeviceConfig::lastSchemaOutcome())
	{
	case DeviceConfig::SchemaOutcome::FreshInstall:  schema = BootSchema::FreshInstall; break;
	case DeviceConfig::SchemaOutcome::AdoptedLegacy:
	case DeviceConfig::SchemaOutcome::UpToDate:
	case DeviceConfig::SchemaOutcome::Migrated:      schema = BootSchema::Upgraded; break;
	default:                                         schema = BootSchema::Uncertain; break;
	}

	const BootModeDecision d = chooseBootMode(haveStored, stored.mode, schema);
	_mode.store(d.mode, std::memory_order_relaxed);
	if (haveStored)
	{
		// #500: this board had stored the retired open mode. It now runs Learn;
		// write that down once so the byte on flash says what the board does.
		if (stored.wasRetiredOpen)
		{
			if (persistMode())
				_env.log("Registrar: stored mode was open, which is retired; now learn, saved (#500)", true);
			else
				_env.log("Registrar: stored mode was open, which is retired; running learn, save FAILED (#500)", true);
		}
		return;
	}

	if (!d.persist)
	{
		_env.log("Registrar: no stored mode and the schema is uncertain; booting learn, not saved (#441)", true);
	}
	else if (persistMode())
	{
		_env.log("Registrar: no stored mode; defaulted to learn and saved it (#397)");
	}
	else
	{
		// persistMode() logged the cause. Safe either way: with no key the next
		// boot decides learn again (chooseBootMode never defaults to open).
		_env.log("Registrar: no stored mode; booting learn, but saving it FAILED (#441)", true);
	}
#endif
}

bool Registrar::persistMode()
{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	// #441 review: every step is checked and a failure is logged with its cause.
	nvs_handle_t h;
	esp_err_t err = nvs_open(pbxpersist::kNvsNamespace, NVS_READWRITE, &h);
	const char* step = "nvs_open";
	if (err == ESP_OK)
	{
		err = nvs_set_u8(h, "reg_mode", static_cast<uint8_t>(_mode.load(std::memory_order_relaxed)));
		step = "nvs_set_u8";
		if (err == ESP_OK)
		{
			err = nvs_commit(h);
			step = "nvs_commit";
		}
		nvs_close(h);
	}
	if (err != ESP_OK)
	{
		_env.log(std::string("Registrar: persisting reg_mode failed at ") + step + " (" +
			esp_err_to_name(err) + ")", true);
		return false;
	}
#endif
	return true;
}

// ── REGISTER admission ────────────────────────────────────────────────────────

void Registrar::sendChallenge(const std::shared_ptr<SipMessage>& data, bool stale)
{
	auto response = _env.messageFromPool(data->toString(), data->getSource());
	if (!response) return;   // pool exhausted: drop, peer retransmits (#101A)
	response->setHeader("SIP/2.0 401 Unauthorized");
	response->clearBody();
	response->setVia(sipwire::viaWithReceived(data->getVia(), data->getSource()));
	response->setTo(std::string(data->getTo()) + ";tag=" + IDGen::GenerateID(9));
	// Fresh stateless nonce per challenge; realm MUST match SipSecretStore::kRealm.
	response->addHeader("WWW-Authenticate",
		SipDigest::buildWwwAuthenticate(SipSecretStore::kRealm,
			SipDigest::generateNonce(), stale));
	response->syncContentLength();
	_env.enqueue(data->getSource(), std::move(response));
}

void Registrar::sendForbidden(const std::shared_ptr<SipMessage>& data, const std::string& reason)
{
	auto response = _env.messageFromPool(data->toString(), data->getSource());
	if (!response) return;   // pool exhausted: drop, peer retransmits (#101A)
	response->setHeader("SIP/2.0 403 " + reason);
	response->clearBody();
	response->setVia(sipwire::viaWithReceived(data->getVia(), data->getSource()));
	response->syncContentLength();
	_env.enqueue(data->getSource(), std::move(response));
}

void Registrar::sendRetryLater(const std::shared_ptr<SipMessage>& data, int retryAfterSeconds)
{
	auto response = _env.messageFromPool(data->toString(), data->getSource());
	if (!response) return;   // pool exhausted: drop, peer retransmits (#101A)
	response->setHeader("SIP/2.0 503 Service Unavailable");
	response->clearBody();
	response->setVia(sipwire::viaWithReceived(data->getVia(), data->getSource()));
	response->addHeader("Retry-After", std::to_string(retryAfterSeconds));
	response->syncContentLength();
	_env.enqueue(data->getSource(), std::move(response));
}

std::unordered_map<std::string, Registrar::DeviceRecord>::iterator Registrar::oldestEvictable()
{
	// Oldest plain Learned entry, offline before online. Locked and Secured
	// entries are never candidates: evicting one would release its extension to
	// whoever registers next. #826: except an unclaimed zero-touch row -- locked
	// to reserve its extension, but no phone has registered it -- which goes
	// first, so unauthenticated config fetches can never pin the table.
	auto victim = _devices.end();
	for (auto it = _devices.begin(); it != _devices.end(); ++it)
	{
		const DeviceRecord& r = it->second;
		if (r.state != DeviceState::Learned || (r.locked && !r.assigned)) continue;
		if (victim == _devices.end())
		{
			victim = it;
			continue;
		}
		const DeviceRecord& v = victim->second;
		const bool better = (r.assigned != v.assigned) ? r.assigned
			: ((v.online != r.online) ? !r.online : (r.seq < v.seq));
		if (better)
		{
			victim = it;
		}
	}
	return victim;
}

bool Registrar::hasEvictable() const
{
	for (const auto& entry : _devices)
	{
		const DeviceRecord& r = entry.second;
		if (r.state == DeviceState::Learned && (!r.locked || r.assigned)) return true;
	}
	return false;
}

Registrar::AuthDecision Registrar::admitSecure(
	const std::shared_ptr<SipMessage>& data, const std::string& ext, std::string& outRejectReason)
{
	// Secure mode: a provisioned extension MUST present a valid digest. An ext with
	// NO stored secret is unprovisioned — reject with a clear reason (the SAFE
	// default; "allow first-time" would defeat the point of secure mode).
	auto ha1 = SipSecretStore::getHa1(ext);
	if (!ha1.has_value())
	{
		outRejectReason = "Extension Not Provisioned";
		_env.log("Secure REGISTER for unprovisioned ext " + ext + " rejected", true);
		return AuthDecision::Reject;
	}

	SipDigest::DigestAuth auth;
	std::string_view authHdr = data->getAuthorization();
	if (authHdr.empty() || !SipDigest::parseAuthorization(std::string(authHdr), auth))
	{
		// No (parseable) credentials → challenge with a fresh nonce.
		sendChallenge(data, /*stale=*/false);
		return AuthDecision::Challenge;
	}

	// Validate the nonce we issued. A forged/garbage nonce is a hard re-challenge
	// (not stale); an expired-but-ours nonce → challenge with stale=true so the
	// phone silently retries.
	bool expired = false;
	if (!SipDigest::validateNonce(auth.nonce, &expired))
	{
		sendChallenge(data, /*stale=*/expired);
		return AuthDecision::Challenge;
	}

	// #512 review (Crew, MEDIUM): the response hash covers auth.uri, not the
	// Request-URI this request is actually routed on. Without this check one
	// captured INVITE's credentials authorise a different destination for the
	// nonce's whole lifetime. RFC 2617 §3.2.2.5: they must be the same URI.
	// (nc/nonce reuse limits are #525.)
	{
		const std::string_view line = data->getHeader();
		const size_t sp1 = line.find(' ');
		const size_t sp2 = sp1 == std::string_view::npos ? sp1 : line.find(' ', sp1 + 1);
		const std::string_view requestUri = sp2 == std::string_view::npos
			? std::string_view{} : line.substr(sp1 + 1, sp2 - sp1 - 1);
		if (requestUri.empty() || auth.uri != requestUri)
		{
			outRejectReason = "Credentials Not For This Request";
			_env.log("Secure " + std::string(data->getType()) + " for ext " + ext +
				": digest uri does not match the Request-URI", true);
			return AuthDecision::Reject;
		}
	}

	// Recompute + constant-time compare. Method is REGISTER.
	if (!SipDigest::verify(auth, *ha1, std::string(data->getType())))
	{
		outRejectReason = "Bad Credentials";
		_env.log("Secure REGISTER for ext " + ext + " failed digest verify", true);
		return AuthDecision::Reject;
	}

	// Issue #525: the credentials are right, but have they been used before?
	// With qop=auth each request carries nc, which must rise per nonce. A
	// repeat is answered with a stale challenge, not a 403: the genuine phone
	// silently retries with a fresh nonce (it has the password), a replayer
	// cannot, and no one is locked out or told anything. Legacy RFC 2069
	// credentials carry no nc and are not checked here (their replay window is
	// the nonce's 5-minute lifetime, as before).
	if (!auth.nc.empty())
	{
		// #525 review: strict -- an RFC 2617 nc-value is exactly 8 hex digits.
		bool ncValid = auth.nc.size() == 8;
		unsigned long nc = 0;
		for (char c : auth.nc)
		{
			const int v = (c >= '0' && c <= '9') ? c - '0'
				: (c >= 'a' && c <= 'f') ? c - 'a' + 10
				: (c >= 'A' && c <= 'F') ? c - 'A' + 10 : -1;
			if (v < 0) { ncValid = false; break; }
			nc = (nc << 4) | static_cast<unsigned long>(v);
		}
		if (!ncValid || !noteNonceUse(auth.nonce, static_cast<uint32_t>(nc), std::chrono::steady_clock::now()))
		{
			_env.log("Secure " + std::string(data->getType()) + " for ext " + ext +
				": digest nonce/nc already used, re-challenged (#525)", true);
			sendChallenge(data, /*stale=*/true);
			return AuthDecision::Challenge;
		}
	}

	return AuthDecision::Accept;
}

bool Registrar::noteNonceUse(const std::string& nonce, uint32_t nc, std::chrono::steady_clock::time_point now)
{
	// validateNonce() has already proved this is one of ours, which always fits;
	// anything longer is not a shape we issue, so there is nothing to track.
	if (nonce.size() >= sizeof(NonceUse::nonce)) return true;
	// Our nonces start with their issue time in hex, up to the '.' (SipDigest.hpp).
	uint64_t issuedMs = 0;
	for (char c : nonce)
	{
		const int v = (c >= '0' && c <= '9') ? c - '0' : (c >= 'a' && c <= 'f') ? c - 'a' + 10 : -1;
		if (v < 0) break;
		issuedMs = (issuedMs << 4) | static_cast<uint64_t>(v);
	}
	NonceUse* victim = nullptr;
	for (NonceUse& u : _nonceUses)
	{
		const bool live = u.until > now;
		if (live && nonce == u.nonce)
		{
			if (nc <= u.nc) return false;   // replay: nc must rise
			u.nc = nc;
			return true;
		}
		// Prefer a dead (expired or never used) slot; else the oldest-issued.
		if (victim == nullptr) { victim = &u; continue; }
		if (victim->until > now && (!live || u.issuedMs < victim->issuedMs)) victim = &u;
	}
	// Unknown here. If a nonce issued this early could have been evicted while
	// live, it may already have been used: re-challenge rather than trust it.
	if (_nonceLiveEvictions > 0 && issuedMs <= _nonceEvictedIssuedMs) return false;
	if (victim->until > now)
	{
		++_nonceLiveEvictions;
		if (victim->issuedMs > _nonceEvictedIssuedMs) _nonceEvictedIssuedMs = victim->issuedMs;
	}
	std::memcpy(victim->nonce, nonce.c_str(), nonce.size() + 1);
	victim->nc = nc;
	victim->issuedMs = issuedMs;
	victim->until = now + std::chrono::milliseconds(SipDigest::kNonceTtlMs);
	return true;
}

Registrar::AuthDecision Registrar::admitLearn(
	const std::shared_ptr<SipMessage>& data, const std::string& ext, std::string& outRejectReason,
	std::chrono::steady_clock::time_point now, bool fromRegisteredAddress)
{
	// Learn mode = TOFU + MAC-lock (issue #440 made the lock real).
	//   ext Secured, or Learn-LOCKED, to a DIFFERENT mac -> reject (anti-spoof).
	//   ARP miss, ext Learn-locked somewhere -> accept from the extension's
	//                            registered IP:port (the owner's refresh), else
	//                            503 + Retry-After (retryable; we cannot tell
	//                            the owner from an impostor yet).
	//   ARP miss otherwise     -> accept + defer, as before (never brick the first
	//                            registration).
	//   UNKNOWN mac            -> accept, record {mac, ext, Learned}, unlocked.
	//   KNOWN mac, same ext    -> the second sighting: LOCK ext to this mac, unless
	//                            an earlier-adopted row holds ext (first claim wins).
	//   KNOWN mac, other ext   -> mark shared (phones behind one NAT router all
	//                            resolve to the router's MAC); a shared MAC never
	//                            locks. A re-provisioned phone looks the same and
	//                            is also left unlocked -- fail open, not locked out.
	//   KNOWN + Secured mac    -> enforce digest (same path as secure mode), and
	//                            never touch its record first (#507).
	//   ARP miss, ext Secured  -> enforce digest; never accept on a miss (#507).
	// A routed off-subnet phone's IP is never in the ARP table, so it always
	// misses: it is never locked, and Learn cannot protect it (use Secure).
	auto lockedElsewhere = [&](const std::string& selfMac) -> const std::string* {
		for (const auto& [m, rec] : _devices)
		{
			if (rec.extension != ext || m == selfMac) continue;
			if (rec.state == DeviceState::Secured || (rec.locked && !rec.shared)) return &m;
		}
		return nullptr;
	};

	auto macOpt = ArpLookup::pdLookupMac(data->getSource());
	if (!macOpt.has_value())
	{
		// #507 finding 1: a Secured extension is AUTHENTICATED, never waved
		// through on a miss. etharp only knows on-link hosts, so an off-subnet or
		// never-ARP'd source always misses (and the host build's lookup always
		// does). The real phone has its credentials, so this breaks nothing that
		// works -- and unlike the retry below, it lets an off-subnet Secured phone
		// register at all.
		if (isExtensionSecured(ext))
		{
			return admitSecure(data, ext, outRejectReason);
		}
		if (const std::string* owner = lockedElsewhere(std::string()))
		{
			if (fromRegisteredAddress)
			{
				// #487 review: the owner's own refresh. lwIP's ARP entries age
				// out, and churn when the table is near the phone count (10 by
				// default; see the top-level CMakeLists.txt), so a locked phone
				// can miss. The binding at
				// this exact IP:port was made by a REGISTER the lock admitted, so
				// this admits no more than an ARP hit on the owner's IP would.
				// Nothing is recorded and the lock is unchanged; a Secured
				// extension never gets here (admitSecure above).
				return AuthDecision::Accept;
			}
			// The owner's ARP entry may simply have aged out. A 403 here would lock
			// the real phone out; accepting would let anyone off-link take the
			// extension. Ask for a retry instead: transmitting this response makes
			// lwIP ARP the source, so an on-link owner resolves next time.
			_env.log("Learn REGISTER ext " + ext + ": ARP miss on an extension locked to " +
				*owner + ", asking for a retry");
			sendRetryLater(data, kLockedArpMissRetrySeconds);
			return AuthDecision::RetryLater;   // response already enqueued
		}
		// Cache miss (or host). Accept now; the server's 200 OK + beep + OPTIONS
		// populates the ARP cache so the NEXT REGISTER resolves. Do NOT hard-fail --
		// that would brick the very first registration.
		_env.log("Learn REGISTER ext " + ext + ": ARP miss, deferring MAC-lock");
		return AuthDecision::Accept;
	}
	const std::string mac = ArpLookup::toHex12(*macOpt);

	if (const std::string* owner = lockedElsewhere(mac))
	{
		outRejectReason = "Extension Locked To Another Device";
		_env.log("Learn REGISTER ext " + ext + " from " + mac +
			" rejected: locked to " + *owner, true);
		return AuthDecision::Reject;
	}

	auto it = _devices.find(mac);
	if (it == _devices.end())
	{
		// First time we've seen this MAC: trust-on-first-use, not yet locked. Bound
		// the table like _dnd/_forwards; when full, evict the oldest plain Learned
		// entry rather than refuse every new phone forever (#440).
		auto victim = _devices.end();
		if (_devices.size() >= static_cast<size_t>(POCKETDIAL_MAX_CLIENTS))
		{
			victim = oldestEvictable();
			if (victim == _devices.end())
			{
				outRejectReason = "Device Table Full";
				_env.log("Learn REGISTER: device table full of locked devices, rejecting " + mac, true);
				return AuthDecision::Reject;
			}
		}
		// #515: spend an adoption token. Credit whole periods since the last
		// refill; a bucket that refills to full restarts its clock at `now`.
		const auto earned = (now - _adoptRefillAt) / kAdoptRefill;
		if (_adoptTokens + earned >= kAdoptBurst)
		{
			_adoptTokens = kAdoptBurst;
			_adoptRefillAt = now;
		}
		else
		{
			_adoptTokens = static_cast<uint8_t>(_adoptTokens + earned);
			_adoptRefillAt += earned * kAdoptRefill;
		}
		if (_adoptTokens == 0)
		{
			// Retryable, unlike the 403s: the phone comes back when a token has.
			const auto wait = std::chrono::ceil<std::chrono::seconds>(_adoptRefillAt + kAdoptRefill - now);
			sendRetryLater(data, static_cast<int>(wait.count()));
			if (_adoptLimitLoggedAt != _adoptRefillAt)
			{
				_adoptLimitLoggedAt = _adoptRefillAt;
				_env.log("Learn: adopt rate limit, 503 " + mac, true);
			}
			return AuthDecision::RetryLater;
		}
		--_adoptTokens;
		// Evict only once the adoption is certain: a rate-limited flood of new
		// MACs must not erase one unlocked device per REGISTER and still be 503'd.
		if (victim != _devices.end())
		{
			_env.log("Learn: device table full, evicting oldest unlocked device " + victim->first +
				" (ext " + victim->second.extension + ")");
			_devices.erase(victim);
		}
		DeviceRecord rec;
		rec.extension = ext;
		rec.state = DeviceState::Learned;
		rec.seq = _nextSeq++;
		_devices.emplace(mac, std::move(rec));
		persistDevices();
		noteChange(Change::Structural);
		_env.log("Learn: adopted device " + mac + " as ext " + ext);
		return AuthDecision::Accept;
	}

	DeviceRecord& rec = it->second;
	if (rec.state == DeviceState::Secured)
	{
		// #507 finding 2: a Secured device's record never moves on a REGISTER.
		// Checked BEFORE anything below touches the record: a single REGISTER for
		// another extension, sent with the source IP forged to this phone's (so
		// ARP returns its real MAC), used to rewrite the record away from its
		// Secured extension -- stripping the lock -- before any digest was checked.
		// The device authenticates for whatever extension it asks for, exactly as
		// secure mode does, and its record stays as it is.
		return admitSecure(data, ext, outRejectReason);
	}

	if (rec.extension != ext && rec.locked && !rec.shared)
	{
		// Crew's #487 review: a LOCKED record never moves on an unauthenticated
		// REGISTER -- the same rule #507 applies to Secured records. One REGISTER
		// for another extension with the locked phone's source IP forged used to
		// release the lock, mark the MAC shared (persisted, so it could never lock
		// again) and let the attacker take the extension. Admit the other
		// extension as TOFU and leave this device's record exactly as it is.
		// Phones behind NAT keep working: the router's MAC stays locked to its
		// first extension, the others register as plain TOFU.
		_env.log("Learn: locked device " + mac + " (ext " + rec.extension + ") registered ext " +
			ext + "; admitted as TOFU, the lock stays");
		return AuthDecision::Accept;
	}

	if (rec.extension != ext)
	{
		// One MAC, a second extension, while still UNLOCKED: phones behind a NAT
		// router, or a phone re-provisioned to a new AOR. Either way this MAC can no
		// longer vouch for one extension, so it stops locking. Keep the extension in
		// sync as before.
		if (!rec.shared)
		{
			rec.shared = true;
			_env.log("Learn: device " + mac + " registered ext " + ext + " after ext " +
				rec.extension + " -- shared MAC (NAT?), its extensions stay unlocked", true);
		}
		rec.locked = false;
		rec.extension = ext;
		persistDevices();
		noteChange(Change::Structural);
	}

	// (A Secured record returned above, before the record could be touched.)
	if (!rec.locked && !rec.shared)
	{
		// #487 review: the lock goes to the extension's FIRST claim, not to the
		// first device to register twice. While an earlier-adopted row still
		// holds ext, this one stays plain TOFU (fail open): otherwise a device
		// that registered after the real phone's first REGISTER could lock it out
		// with two packets of its own (an expires=0 counts).
		for (const auto& [m, other] : _devices)
		{
			if (m != mac && other.extension == ext && other.seq < rec.seq) return AuthDecision::Accept;
		}
		// Second sighting of this MAC for this extension: bind it.
		rec.locked = true;
		persistDevices();
		noteChange(Change::Structural);
		_env.log("Learn: locked ext " + ext + " to device " + mac);
	}
	return AuthDecision::Accept;
}

// ── Adopted-device registry ───────────────────────────────────────────────────

std::unordered_map<std::string, Registrar::DeviceRecord>::iterator
Registrar::findDevice(const std::string& macOrExt)
{
	// Accept either a 12-hex MAC (direct key) or an extension (find the device
	// currently adopted under it).
	auto it = _devices.find(macOrExt);
	if (it == _devices.end())
	{
		// Several rows can hold one extension (#440: the owner's lock beside a
		// later claim that never locked). Act on the one that holds it: Secured,
		// then Learn-locked, then the first claim (lowest seq). Map order would
		// let "secure 201" promote a stray row and lock the owner out.
		auto rank = [](const DeviceRecord& r) {
			if (r.state == DeviceState::Secured) return 0;
			return (r.locked && !r.shared) ? 1 : 2;
		};
		for (auto cand = _devices.begin(); cand != _devices.end(); ++cand)
		{
			if (cand->second.extension != macOrExt) continue;
			if (it == _devices.end() || rank(cand->second) < rank(it->second) ||
				(rank(cand->second) == rank(it->second) && cand->second.seq < it->second.seq))
			{
				it = cand;
			}
		}
	}
	return it;
}

void Registrar::markOnline(const std::string& mac, bool online)
{
	auto it = _devices.find(mac);
	if (it == _devices.end())
	{
		return;
	}
	if (online && it->second.assigned)
	{
		// #826: the phone a zero-touch row was made for has registered: claimed.
		// From here it is an ordinary locked row, never evicted.
		it->second.assigned = false;
		it->second.online = true;
		persistDevices();
		noteChange(Change::Structural);
		_env.log("Learn: zero-touch device " + mac + " claimed ext " + it->second.extension);
		return;
	}
	if (it->second.online != online)
	{
		it->second.online = online;
		// Row set is unchanged — the mirror only needs the flag patched, not a
		// rebuild of every mac/extension string.
		noteChange(Change::OnlineOnly);
	}
}

bool Registrar::secure(const std::string& macOrExt)
{
	bool changed = false;
	auto it = findDevice(macOrExt);
	if (it != _devices.end())
	{
		// Footgun guard: promoting a device to Secured makes admitSecure() demand a
		// digest for it. If the extension has NO stored secret, that would lock the
		// phone out on its next REGISTER ("Extension Not Provisioned"). Refuse, and
		// tell the operator to assign a secret first.
		if (!SipSecretStore::hasSecret(it->second.extension))
		{
			_env.log("secureDevice: ext " + it->second.extension +
				" has no SIP secret — assign one before securing", true);
		}
		else
		{
			if (it->second.state != DeviceState::Secured)
			{
				it->second.state = DeviceState::Secured;
				persistDevices();
				changed = true;
				noteChange(Change::Structural);
			}
			_env.log("Device " + it->first + " (ext " + it->second.extension + ") secured");
		}
	}
	else
	{
		_env.log("secureDevice: no adopted device for '" + macOrExt + "'", true);
	}
	return changed;
}

bool Registrar::forget(const std::string& macOrExt)
{
	auto it = findDevice(macOrExt);
	if (it == _devices.end())
	{
		_env.log("forgetDevice: no adopted device for '" + macOrExt + "'", true);
		return false;
	}
	_env.log("Device " + it->first + " (ext " + it->second.extension + ") forgotten");
	_devices.erase(it);
	persistDevices();
	noteChange(Change::Structural);
	return true;
}

size_t Registrar::forgetLearned()
{
	size_t n = 0;
	for (auto it = _devices.begin(); it != _devices.end();)
	{
		if (it->second.state == DeviceState::Learned) { it = _devices.erase(it); ++n; }
		else ++it;
	}
	if (n == 0) return 0;
	persistDevices();
	noteChange(Change::Structural);
	_env.log("Learn: forgot " + std::to_string(n) + " learned");
	return n;
}

std::vector<Registrar::AdoptedDevice> Registrar::adoptedDevices() const
{
	std::vector<AdoptedDevice> out;
	out.reserve(_devices.size());
	for (const auto& [mac, rec] : _devices)
	{
		AdoptedDevice d;
		d.mac = mac;
		d.extension = rec.extension;
		d.state = rec.state;
		d.online = rec.online;
		d.locked = rec.locked;
		d.shared = rec.shared;
		d.assigned = rec.assigned;
		out.push_back(std::move(d));
	}
	return out;
}

bool Registrar::isExtensionSecured(std::string_view ext) const
{
	for (const auto& [mac, rec] : _devices)
	{
		if (rec.extension == ext && rec.state == DeviceState::Secured) return true;
	}
	return false;
}

bool Registrar::extensionOf(std::string_view mac, std::string_view& ext) const
{
	for (const auto& entry : _devices)
	{
		if (entry.first == mac)
		{
			ext = entry.second.extension;
			return true;
		}
	}
	return false;
}

// ── Zero-touch assignment (#826 part B) ───────────────────────────────────────

int Registrar::encodeRowFlags(const RowFlags& f)
{
	return (f.locked ? 1 : 0) | (f.shared ? 2 : 0) | (f.assigned ? 4 : 0);
}

Registrar::RowFlags Registrar::decodeRowFlags(int flags)
{
	RowFlags f;
	f.locked = (flags & 1) != 0;
	f.shared = (flags & 2) != 0;
	f.assigned = (flags & 4) != 0;
	return f;
}

bool Registrar::openAssignWindow(uint32_t lo, uint32_t hi, std::chrono::steady_clock::time_point until)
{
	if (lo > hi || hi - lo >= kMaxAssignSpan) return false;
	_assign = AssignWindow{true, lo, hi, until};
	return true;
}

Registrar::AssignWindow Registrar::assignWindow(std::chrono::steady_clock::time_point now) const
{
	if (_assign.open && now < _assign.until) return _assign;
	return AssignWindow{};
}

std::size_t Registrar::unclaimedCount() const
{
	std::size_t n = 0;
	for (const auto& entry : _devices)
	{
		if (entry.second.assigned) ++n;
	}
	return n;
}

uint8_t Registrar::adoptTokensAt(std::chrono::steady_clock::time_point now) const
{
	if (now <= _adoptRefillAt) return _adoptTokens;
	const auto earned = (now - _adoptRefillAt) / kAdoptRefill;
	const auto total = static_cast<long long>(_adoptTokens) + static_cast<long long>(earned);
	return (total >= kAdoptBurst) ? kAdoptBurst : static_cast<uint8_t>(total);
}

// The same arithmetic as admitLearn()'s inline #515 bucket, on the same state.
bool Registrar::takeAdoptToken(std::chrono::steady_clock::time_point now)
{
	const auto earned = (now > _adoptRefillAt) ? (now - _adoptRefillAt) / kAdoptRefill : 0;
	if (_adoptTokens + earned >= kAdoptBurst)
	{
		_adoptTokens = kAdoptBurst;
		_adoptRefillAt = now;
	}
	else
	{
		_adoptTokens = static_cast<uint8_t>(_adoptTokens + earned);
		_adoptRefillAt += earned * kAdoptRefill;
	}
	if (_adoptTokens == 0) return false;
	--_adoptTokens;
	return true;
}

bool Registrar::pickFreeExtension(std::chrono::steady_clock::time_point now,
	FunctionRef<bool(const std::string&)> unusable, std::string& out) const
{
	const AssignWindow w = assignWindow(now);
	if (!w.open) return false;
	for (uint32_t i = 0; i < kMaxAssignSpan && w.lo + i <= w.hi; ++i)
	{
		std::string cand = std::to_string(w.lo + i);
		bool held = false;
		for (const auto& entry : _devices)
		{
			if (entry.second.extension == cand) { held = true; break; }
		}
		if (held || unusable(cand)) continue;
		out = std::move(cand);
		return true;
	}
	return false;
}

bool Registrar::canAssign(const std::string& mac, std::chrono::steady_clock::time_point now,
	FunctionRef<bool(const std::string&)> unusable) const
{
	if (_devices.count(mac) != 0) return true;
	if (!assignWindow(now).open || unclaimedCount() >= kMaxUnclaimed) return false;
	if (_devices.size() >= static_cast<size_t>(POCKETDIAL_MAX_CLIENTS) && !hasEvictable()) return false;
	if (adoptTokensAt(now) == 0) return false;
	std::string ext;
	return pickFreeExtension(now, unusable, ext);
}

bool Registrar::assignNext(const std::string& mac, std::chrono::steady_clock::time_point now,
	FunctionRef<bool(const std::string&)> unusable, std::string& outExt)
{
	auto it = _devices.find(mac);
	if (it != _devices.end())
	{
		outExt = it->second.extension;   // same MAC, same extension; nothing spent
		return true;
	}
	if (!assignWindow(now).open || unclaimedCount() >= kMaxUnclaimed) return false;
	std::string ext;
	if (!pickFreeExtension(now, unusable, ext)) return false;
	// #487 order: choose the victim, spend the token, and only then erase. A
	// refusal for want of a token leaves the table exactly as it was.
	auto victim = _devices.end();
	if (_devices.size() >= static_cast<size_t>(POCKETDIAL_MAX_CLIENTS))
	{
		victim = oldestEvictable();
		if (victim == _devices.end()) return false;
	}
	if (!takeAdoptToken(now)) return false;
	if (victim != _devices.end())
	{
		_env.log("Learn: device table full, evicting " + victim->first + " (ext " +
			victim->second.extension + ") for a zero-touch assignment");
		_devices.erase(victim);
	}
	DeviceRecord rec;
	rec.extension = ext;
	rec.state = DeviceState::Learned;
	rec.locked = true;
	rec.assigned = true;
	rec.seq = _nextSeq++;
	_devices.emplace(mac, std::move(rec));
	persistDevices();
	noteChange(Change::Structural);
	_env.log("Learn: zero-touch assigned ext " + ext + " to device " + mac);
	outExt = ext;
	return true;
}

void Registrar::noteChange(Change kind)
{
	// The enum is ordered None < OnlineOnly < Structural, so taking the max keeps
	// Structural sticky: once the row set gained or lost an entry in this pass, a
	// later online flip must not downgrade it to the patch-only path.
	_devicesChanged = std::max(_devicesChanged, kind);
}

Registrar::Change Registrar::consumeDevicesChange()
{
	Change was = _devicesChanged;
	_devicesChanged = Change::None;
	return was;
}

void Registrar::copyOnlineFlagsInto(std::vector<AdoptedDevice>& rows) const
{
	for (auto& row : rows)
	{
		auto it = _devices.find(row.mac);
		if (it != _devices.end()) row.online = it->second.online;
	}
}

void Registrar::loadDevices()
{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	nvs_handle_t h;
	if (nvs_open(pbxpersist::kNvsNamespace, NVS_READWRITE, &h) != ESP_OK)
	{
		return;
	}
	size_t len = 0;
	if (nvs_get_str(h, "devices", nullptr, &len) == ESP_OK && len > 0)
	{
		std::string buf(len, '\0');
		if (nvs_get_str(h, "devices", buf.data(), &len) == ESP_OK)
		{
			if (!buf.empty() && buf.back() == '\0') buf.pop_back();
			// Record: mac \t extension \t state(int) [\t flags(int) \t seq(u32)]
			// The last two fields are #440's (flags: bit0 locked, bit1 shared). A
			// pre-#440 blob has three fields and loads unlocked. Pre-#440 firmware
			// reads only the first three of a new blob, so a downgrade boots, but
			// its next write drops both fields: a downgrade releases every lock.
			for (const auto& rec : pbxpersist::deserializeBlob(buf))
			{
				if (rec.size() < 3 || rec[0].empty()) continue;
				if (_devices.size() >= static_cast<size_t>(POCKETDIAL_MAX_CLIENTS)) break;
				DeviceRecord r;
				r.extension = rec[1];
				int si = atoi(rec[2].c_str());
				r.state = (si == static_cast<int>(DeviceState::Secured))
					? DeviceState::Secured : DeviceState::Learned;
				if (rec.size() >= 5)
				{
					const RowFlags flags = decodeRowFlags(atoi(rec[3].c_str()));
					r.locked = flags.locked;
					r.shared = flags.shared;
					r.assigned = flags.assigned;
					// Clamped: a saved UINT32_MAX would wrap _nextSeq to 0 below, and
					// every later adoption would then sort as the oldest (evicted first).
					const unsigned long saved = strtoul(rec[4].c_str(), nullptr, 10);
					r.seq = (saved < 0x80000000UL) ? static_cast<uint32_t>(saved) : 0;
				}
				if (r.seq == 0) r.seq = _nextSeq;   // pre-#440 (or out-of-range) row: order as loaded
				if (r.seq >= _nextSeq) _nextSeq = r.seq + 1;
				_devices[rec[0]] = std::move(r);
			}
		}
	}
	nvs_close(h);
	if (!_devices.empty()) noteChange(Change::Structural);
#endif
}

bool Registrar::persistDevices()
{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	// mac \t extension \t state(int) \t flags(int) \t seq(u32); the last two are
	// #440's (see loadDevices()). Bounded by POCKETDIAL_MAX_CLIENTS, so the blob
	// is fixed-footprint. Write-through after each adoption / secure / forget. Caller
	// holds _mutex; online state is NOT persisted (it is volatile registration state).
	std::string blob;
	for (const auto& [mac, rec] : _devices)
	{
		blob += mac; blob += '\t';
		blob += rec.extension; blob += '\t';
		blob += std::to_string(static_cast<int>(rec.state)); blob += '\t';
		blob += std::to_string(encodeRowFlags(RowFlags{rec.locked, rec.shared, rec.assigned})); blob += '\t';
		blob += std::to_string(rec.seq); blob += '\n';
	}
	// Every NVS return is checked (Crew's #487 review): the lock and shared flags
	// live only here, so a silently failed write would revert locks on the next
	// reboot. Logged at error; callers carry on (the in-RAM table is still right).
	nvs_handle_t h;
	const esp_err_t openErr = nvs_open(pbxpersist::kNvsNamespace, NVS_READWRITE, &h);
	if (openErr != ESP_OK)
	{
		_env.log(std::string("Registrar: persisting the device table failed at open (") +
			esp_err_to_name(openErr) + ")", true);
		return false;
	}
	const esp_err_t setErr = nvs_set_str(h, "devices", blob.c_str());
	const esp_err_t commitErr = (setErr == ESP_OK) ? nvs_commit(h) : setErr;
	nvs_close(h);
	if (setErr != ESP_OK || commitErr != ESP_OK)
	{
		_env.log(std::string("Registrar: persisting the device table FAILED (") +
			esp_err_to_name(setErr != ESP_OK ? setErr : commitErr) + ")", true);
		return false;
	}
	return true;
#else
	return true;
#endif
}
