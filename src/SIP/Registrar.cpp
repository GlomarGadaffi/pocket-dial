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
		char* end = nullptr;
		const unsigned long nc = std::strtoul(auth.nc.c_str(), &end, 16);
		const bool ncValid = end != auth.nc.c_str() && *end == '\0' && nc <= 0xFFFFFFFFul;
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
	NonceUse* victim = &_nonceUses[0];
	for (NonceUse& u : _nonceUses)
	{
		if (u.until > now && nonce == u.nonce)
		{
			if (nc <= u.nc) return false;   // replay: nc must rise
			u.nc = nc;
			return true;
		}
		if (u.until < victim->until) victim = &u;   // expired (or never used) first
	}
	std::memcpy(victim->nonce, nonce.c_str(), nonce.size() + 1);
	victim->nc = nc;
	victim->until = now + std::chrono::milliseconds(SipDigest::kNonceTtlMs);
	return true;
}

Registrar::AuthDecision Registrar::admitLearn(
	const std::shared_ptr<SipMessage>& data, const std::string& ext, std::string& outRejectReason)
{
	// Learn mode = TOFU + MAC-lock.
	//   UNKNOWN mac            -> accept WITHOUT verifying, record {mac, ext, Learned}.
	//   KNOWN + Secured mac    -> enforce digest (same path as secure mode).
	//   ext Secured to a DIFFERENT mac -> reject (anti-spoof lock).
	//   first-packet ARP miss  -> accept + defer the lock to the next REGISTER.
	auto macOpt = ArpLookup::pdLookupMac(data->getSource());
	if (!macOpt.has_value())
	{
		// Cache miss (or host). Accept now; the server's 200 OK + beep + OPTIONS
		// populates the ARP cache so the NEXT REGISTER resolves and locks. Do NOT
		// hard-fail — that would brick the very first registration.
		_env.log("Learn REGISTER ext " + ext + ": ARP miss, deferring MAC-lock");
		return AuthDecision::Accept;
	}
	const std::string mac = ArpLookup::toHex12(*macOpt);

	// Anti-spoof: if this extension is already Secured to a DIFFERENT mac, reject.
	for (const auto& [m, rec] : _devices)
	{
		if (rec.extension == ext && rec.state == DeviceState::Secured && m != mac)
		{
			outRejectReason = "Extension Locked To Another Device";
			_env.log("Learn REGISTER ext " + ext + " from " + mac +
				" rejected: locked to " + m, true);
			return AuthDecision::Reject;
		}
	}

	auto it = _devices.find(mac);
	if (it == _devices.end())
	{
		// First time we've seen this MAC: trust-on-first-use. Bound the table like
		// _dnd/_forwards — a flood of distinct MACs can't grow the heap unbounded.
		if (_devices.size() >= static_cast<size_t>(POCKETDIAL_MAX_CLIENTS))
		{
			outRejectReason = "Device Table Full";
			_env.log("Learn REGISTER: device table full, rejecting " + mac, true);
			return AuthDecision::Reject;
		}
		DeviceRecord rec;
		rec.extension = ext;
		rec.state = DeviceState::Learned;
		_devices.emplace(mac, std::move(rec));
		persistDevices();
		noteChange(Change::Structural);
		_env.log("Learn: adopted device " + mac + " as ext " + ext);
		return AuthDecision::Accept;
	}

	// Known MAC. Keep its extension in sync if the phone re-provisioned to a new AOR.
	if (it->second.extension != ext)
	{
		it->second.extension = ext;
		persistDevices();
		noteChange(Change::Structural);
	}

	if (it->second.state == DeviceState::Secured)
	{
		// Promoted device: enforce digest exactly as secure mode does.
		return admitSecure(data, ext, outRejectReason);
	}

	// Known + still Learned → accept (TOFU continues until an admin secures it).
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
			// Record: mac \t extension \t state(int)
			for (const auto& rec : pbxpersist::deserializeBlob(buf))
			{
				if (rec.size() < 3 || rec[0].empty()) continue;
				if (_devices.size() >= static_cast<size_t>(POCKETDIAL_MAX_CLIENTS)) break;
				DeviceRecord r;
				r.extension = rec[1];
				int si = atoi(rec[2].c_str());
				r.state = (si == static_cast<int>(DeviceState::Secured))
					? DeviceState::Secured : DeviceState::Learned;
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
		blob += std::to_string(static_cast<int>(rec.state)); blob += '\n';
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
