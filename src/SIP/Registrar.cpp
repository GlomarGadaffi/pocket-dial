#include "Registrar.hpp"
#include "SipWireUtil.hpp"

#include <algorithm>
#include <cstdlib>

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
	const char* name = (mode == Mode::Open)  ? "open"
	                 : (mode == Mode::Learn) ? "learn"
	                                         : "secure";
	_env.log(std::string("Registrar mode set to ") + name);
}

Registrar::BootModeDecision Registrar::chooseBootMode(bool haveStored, Mode stored, BootSchema schema)
{
	// #441 review: NO path without a stored mode ends in Open. A missing key is
	// what every failure looks like -- a persist that failed on a fresh board, a
	// factory reset whose write failed, an unreadable store -- so it must mean
	// the safe mode, never the permissive one. The existing deployments that
	// must keep Open get it WRITTEN by the schema v1 -> v2 migration
	// (DeviceConfig::schemaMigrations), which stamps v2 only once the write
	// succeeded; they arrive here with haveStored == true.
	if (haveStored) return {stored, false};
	// Learn, not Open: it still admits every first REGISTER, so phones keep
	// working, but no board is left accepting anything forever. Persist only when
	// the store is trusted; an uncertain one is re-decided on the next boot.
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
	const bool haveStored = (err == ESP_OK && v <= static_cast<uint8_t>(Mode::Secure));
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

	const BootModeDecision d = chooseBootMode(haveStored, static_cast<Mode>(v), schema);
	_mode.store(d.mode, std::memory_order_relaxed);
	if (haveStored) return;

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

bool Registrar::evictOneLearned()
{
	// Oldest plain Learned entry, offline before online. Locked and Secured
	// entries are never candidates: evicting one would release its extension to
	// whoever registers next.
	auto victim = _devices.end();
	for (auto it = _devices.begin(); it != _devices.end(); ++it)
	{
		const DeviceRecord& r = it->second;
		if (r.state != DeviceState::Learned || r.locked) continue;
		if (victim == _devices.end() ||
			(victim->second.online && !r.online) ||
			(victim->second.online == r.online && r.seq < victim->second.seq))
		{
			victim = it;
		}
	}
	if (victim == _devices.end()) return false;
	_env.log("Learn: device table full, evicting oldest unlocked device " + victim->first +
		" (ext " + victim->second.extension + ")");
	_devices.erase(victim);
	return true;
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

	// Recompute + constant-time compare. Method is REGISTER.
	if (!SipDigest::verify(auth, *ha1, std::string(data->getType())))
	{
		outRejectReason = "Bad Credentials";
		_env.log("Secure REGISTER for ext " + ext + " failed digest verify", true);
		return AuthDecision::Reject;
	}

	return AuthDecision::Accept;
}

Registrar::AuthDecision Registrar::admitLearn(
	const std::shared_ptr<SipMessage>& data, const std::string& ext, std::string& outRejectReason)
{
	// Learn mode = TOFU + MAC-lock (issue #440 made the lock real).
	//   ext Secured, or Learn-LOCKED, to a DIFFERENT mac -> reject (anti-spoof).
	//   ARP miss, ext locked/Secured somewhere -> 503 + Retry-After (retryable;
	//                            we cannot tell the owner from an impostor yet).
	//   ARP miss otherwise     -> accept + defer, as before (never brick the first
	//                            registration).
	//   UNKNOWN mac            -> accept, record {mac, ext, Learned}, unlocked.
	//   KNOWN mac, same ext    -> the second sighting: LOCK ext to this mac.
	//   KNOWN mac, other ext   -> mark shared (phones behind one NAT router all
	//                            resolve to the router's MAC); a shared MAC never
	//                            locks. A re-provisioned phone looks the same and
	//                            is also left unlocked -- fail open, not locked out.
	//   KNOWN + Secured mac    -> enforce digest (same path as secure mode).
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
		if (const std::string* owner = lockedElsewhere(std::string()))
		{
			// The owner's ARP entry may simply have aged out. A 403 here would lock
			// the real phone out; accepting would let anyone off-link take the
			// extension. Ask for a retry instead: transmitting this response makes
			// lwIP ARP the source, so an on-link owner resolves next time.
			_env.log("Learn REGISTER ext " + ext + ": ARP miss on an extension locked to " +
				*owner + ", asking for a retry");
			sendRetryLater(data, kLockedArpMissRetrySeconds);
			return AuthDecision::Challenge;   // response already enqueued
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
		if (_devices.size() >= static_cast<size_t>(POCKETDIAL_MAX_CLIENTS) && !evictOneLearned())
		{
			outRejectReason = "Device Table Full";
			_env.log("Learn REGISTER: device table full of locked devices, rejecting " + mac, true);
			return AuthDecision::Reject;
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
	if (rec.extension != ext)
	{
		// One MAC, a second extension: phones behind a NAT router, or a phone
		// re-provisioned to a new AOR. Either way this MAC can no longer vouch for
		// one extension, so it stops locking. Keep the extension in sync as before.
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

	if (rec.state == DeviceState::Secured)
	{
		// Promoted device: enforce digest exactly as secure mode does.
		return admitSecure(data, ext, outRejectReason);
	}

	if (!rec.locked && !rec.shared)
	{
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
		for (auto cand = _devices.begin(); cand != _devices.end(); ++cand)
		{
			if (cand->second.extension == macOrExt) { it = cand; break; }
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
		out.push_back(std::move(d));
	}
	return out;
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
			// pre-#440 blob has three fields and loads unlocked; pre-#440 firmware
			// reads only the first three of a new blob, so both directions work.
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
					const int flags = atoi(rec[3].c_str());
					r.locked = (flags & 1) != 0;
					r.shared = (flags & 2) != 0;
					r.seq = static_cast<uint32_t>(strtoul(rec[4].c_str(), nullptr, 10));
				}
				if (r.seq == 0) r.seq = _nextSeq;   // pre-#440 row: order as loaded
				if (r.seq >= _nextSeq) _nextSeq = r.seq + 1;
				_devices[rec[0]] = std::move(r);
			}
		}
	}
	nvs_close(h);
	if (!_devices.empty()) noteChange(Change::Structural);
#endif
}

void Registrar::persistDevices()
{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	// mac \t extension \t state(int). Bounded by POCKETDIAL_MAX_CLIENTS, so the blob
	// is fixed-footprint. Write-through after each adoption / secure / forget. Caller
	// holds _mutex; online state is NOT persisted (it is volatile registration state).
	std::string blob;
	for (const auto& [mac, rec] : _devices)
	{
		blob += mac; blob += '\t';
		blob += rec.extension; blob += '\t';
		blob += std::to_string(static_cast<int>(rec.state)); blob += '\t';
		blob += std::to_string((rec.locked ? 1 : 0) | (rec.shared ? 2 : 0)); blob += '\t';
		blob += std::to_string(rec.seq); blob += '\n';
	}
	nvs_handle_t h;
	if (nvs_open(pbxpersist::kNvsNamespace, NVS_READWRITE, &h) == ESP_OK)
	{
		nvs_set_str(h, "devices", blob.c_str());
		nvs_commit(h);
		nvs_close(h);
	}
#endif
}
