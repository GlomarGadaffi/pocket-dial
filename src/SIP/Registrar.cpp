#include "Registrar.hpp"
#include "SipWireUtil.hpp"

#include <algorithm>
#include <cstdlib>

#include "ArpLookup.hpp"
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

void Registrar::loadMode()
{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	nvs_handle_t h;
	if (nvs_open(pbxpersist::kNvsNamespace, NVS_READWRITE, &h) != ESP_OK)
	{
		return;
	}
	uint8_t v = 0;
	esp_err_t err = nvs_get_u8(h, "reg_mode", &v);
	nvs_close(h);
	if (err == ESP_OK && v <= static_cast<uint8_t>(Mode::Secure))
	{
		_mode.store(static_cast<Mode>(v), std::memory_order_relaxed);
	}
	// else: keep the compile-time-seeded default (Open under POCKETDIAL_OPEN_REGISTRAR).
#endif
}

void Registrar::persistMode()
{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	nvs_handle_t h;
	if (nvs_open(pbxpersist::kNvsNamespace, NVS_READWRITE, &h) == ESP_OK)
	{
		nvs_set_u8(h, "reg_mode",
			static_cast<uint8_t>(_mode.load(std::memory_order_relaxed)));
		nvs_commit(h);
		nvs_close(h);
	}
#endif
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
