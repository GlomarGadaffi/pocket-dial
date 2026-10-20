#include "TelephonyApiConfig.hpp"

#include "EmergencyCall.hpp"
#include "NvsWriter.hpp"
#include "ResetGuard.hpp"

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <algorithm>
#include <string_view>

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	// Persisted in a DEDICATED NVS namespace ("tapicfg") so a factory-reset of
	// the PBX config ("pbxcfg") never collaterally wipes — or accidentally
	// dumps — API credentials. NOTE: values are plaintext in flash unless the
	// device enables flash encryption + NVS encryption; see the header's
	// secret-handling model.
	#include "nvs_flash.h"
	#include "nvs.h"
	#include "esp_log.h"
#else
	// Host fallback: a plaintext key=value file created with 0600 permissions.
	#include <sys/stat.h>
	#include <sys/types.h>
	#include <fcntl.h>
	#if !defined(_WIN32)
		#include <unistd.h>
	#endif
	#include <fstream>
	#include <sstream>
#endif

namespace
{
	constexpr const char* kNvsNamespace = "tapicfg";

	// NVS keys are capped at 15 chars; "s0url".."s3dn" + "active" all fit.
	void slotKey(char* out, size_t outLen, size_t idx, const char* field)
	{
		std::snprintf(out, outLen, "s%u%s", static_cast<unsigned>(idx), field);
	}

	bool validProviderByte(uint8_t v)
	{
		return v < static_cast<uint8_t>(TelephonyProviderType::Count);
	}

	// #1060: a store written before the #1047 refusal can hold an emergency routeDn, and the
	// boot path copies an enabled slot's routeDn into the anchor config. load() runs this on
	// each slot it read: such a slot comes up disabled (the stored value is left for the
	// operator to see and replace). RAM only; the next save writes the table.
	void refuseStoredEmergencyRouteDn(TelephonyApiConfig::Slot& s, size_t idx)
	{
		if (!isEmergencyRouteDn(s.routeDn)) return;
		s.enabled = false;
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
		ESP_LOGW("tapicfg", "slot %u: stored route DN is an emergency number, slot disabled", static_cast<unsigned>(idx));
#else
		std::fprintf(stderr, "tapicfg: slot %u: stored route DN is an emergency number, slot disabled\n", static_cast<unsigned>(idx));
#endif
	}
}

void TelephonyApiConfig::scrub(std::string& s)
{
	// Best-effort zeroize: overwrite the live storage before clearing so the
	// plaintext doesn't linger in the freed buffer. (std::string may have made
	// earlier copies during edits — hygiene, not a guarantee.)
	if (!s.empty())
	{
		std::fill(s.begin(), s.end(), '\0');
	}
	s.clear();
}

TelephonyApiConfig::SlotView TelephonyApiConfig::view(size_t idx) const
{
	SlotView v;
	if (idx >= kSlots)
	{
		return v;
	}
	const Slot& s = _slots[idx];
	v.type        = s.type;
	v.enabled     = s.enabled;
	v.implemented = telephonyProviderImplemented(s.type);
	v.active      = (_active == idx);
	v.baseUrl     = s.baseUrl;
	v.clientId    = s.clientId;
	v.routeDn     = s.routeDn;
	v.secretSet   = !s.secret.empty();   // the value itself never leaves
	return v;
}

const TelephonyApiConfig::Slot* TelephonyApiConfig::bootSlot(size_t idx) const
{
	return (idx < kSlots) ? &_slots[idx] : nullptr;
}

bool isEmergencyRouteDn(std::string_view dn)
{
	// 112 and 113 are not in classifyEmergencyDial()'s set (EmergencyCall.hpp), so they are
	// listed here and only here. This decides the test dial and the slot write; it does not
	// touch the real 911/933 routing.
	return pbx::classifyEmergencyDial(dn).isEmergency || dn == "112" || dn == "113";
}

std::string TelephonyApiConfig::setSlot(size_t idx, const Slot& s, bool keepSecret)
{
	if (idx >= kSlots)
	{
		return "Bad slot index";
	}
	if (static_cast<size_t>(s.type) >= static_cast<size_t>(TelephonyProviderType::Count))
	{
		return "Unknown provider type";
	}
	if (s.baseUrl.size() > kMaxUrlLen)
	{
		return "Base URL too long";
	}
	if (s.clientId.size() > kMaxFieldLen || s.secret.size() > kMaxFieldLen ||
	    s.routeDn.size() > kMaxFieldLen)
	{
		return "Field too long";
	}
	if (isEmergencyRouteDn(s.routeDn))
	{
		// #1047: testDialSlot() self-dials routeDn, so an emergency number here would have the
		// provider place a real emergency call. Refused enabled or not, before anything is staged.
		return "Route DN may not be an emergency number";
	}
	if (s.enabled && s.type != TelephonyProviderType::Loopback)
	{
		// An ENABLED slot must be dialable: real provider, https endpoint, and
		// enough identity to actually originate.
		if (s.baseUrl.rfind("https://", 0) != 0)
		{
			return "Enabled slot needs an https:// base URL";
		}
		// A blank route DN is the one misconfiguration nothing downstream can
		// report. isConnected() is WebSocket state only and the control socket
		// carries no DN, so the board comes up "connected", every makeCall
		// builds ".../callcontrol//makecall", the provider is genuinely reached
		// and answers non-2xx — which reads in the field as "the API was hit but
		// no call happened". Refuse it here, at the only place that can tell.
		if (s.routeDn.empty())
		{
			return "Enabled slot needs a route DN";
		}
		if (s.clientId.empty())
		{
			return "Enabled slot needs a client ID";
		}
		// keepSecret means "leave the stored secret alone", so validate the
		// EFFECTIVE secret rather than the (deliberately empty) incoming one.
		if ((keepSecret ? _slots[idx].secret : s.secret).empty())
		{
			return "Enabled slot needs a client secret";
		}
	}

	Slot& dst = _slots[idx];
	dst.type     = s.type;
	dst.enabled  = s.enabled;
	dst.baseUrl  = s.baseUrl;
	dst.clientId = s.clientId;
	dst.routeDn  = s.routeDn;
	if (!keepSecret)
	{
		// Pending only when the value really differs from the live one (compared
		// BEFORE it is replaced): re-saving the same secret writes nothing. The flag,
		// not a comparison at write time, is what a failed write is retried by.
		if (s.secret != dst.secret)
		{
			_secretPending[idx] = true;
		}
		scrub(dst.secret);
		dst.secret = s.secret;
	}
	return persist();
}

void TelephonyApiConfig::wipeSlot(size_t idx)
{
	Slot& s = _slots[idx];
	if (!s.secret.empty())
	{
		_secretPending[idx] = true;   // the stored secret must be erased too
	}
	scrub(s.secret);
	scrub(s.baseUrl);
	scrub(s.clientId);
	scrub(s.routeDn);
	s.type = TelephonyProviderType::Loopback;
	s.enabled = false;
	if (_active == idx)
	{
		_active = kNoActiveSlot;
	}
}

std::string TelephonyApiConfig::clearSlot(size_t idx)
{
	if (idx >= kSlots)
	{
		return "Bad slot index";
	}
	wipeSlot(idx);
	return persist();
}

std::string TelephonyApiConfig::clearAll()
{
	// Every slot wiped in RAM first (zeroize + clear-active-if-needed, the same
	// wipeSlot() clearSlot() uses), then ONE synchronous write of the empty table:
	// the factory reset runs this after resetguard::begin(), when a staged write is
	// refused, and it reports whether the credentials are really gone. The
	// in-memory secrets are zeroized whatever the write returns.
	for (size_t i = 0; i < kSlots; ++i)
	{
		wipeSlot(i);
	}
	_active = kNoActiveSlot;
	const std::string err = persistNow();
	if (err.empty())
	{
		std::fill(std::begin(_secretPending), std::end(_secretPending), false);   // every secret key was just written empty
	}
	return err;
}

std::string TelephonyApiConfig::setActiveSlot(size_t idx)
{
	if (idx != kNoActiveSlot && idx >= kSlots)
	{
		return "Bad slot index";
	}
	_active = idx;
	return persist();
}

// ── Staged persistence (#986, #997) ───────────────────────────────────────────

bool TelephonyApiConfig::anySecretPending() const
{
	return std::any_of(std::begin(_secretPending), std::end(_secretPending), [](bool p) { return p; });
}

// Fixed layout, built in the writer's staging slot: no heap, no stack buffer. A value
// is taken as its C string (what nvs_set_str(value.c_str()) stored), then NUL-padded
// to its cell; one longer than a cell is refused whole, never cut short. THE SECRET
// IS NOT HERE and must never be: this runs under _mutex into a slot nothing zeroises.
void TelephonyApiConfig::fillSnapshot(nvswriter::BlobWriter& w) const
{
	auto cell = [&w](const char* v) {
		const size_t n = std::strlen(v);
		if (n >= kCellLen)
		{
			w.fail();
			return;
		}
		w.str(std::string_view(v, n));
		for (size_t pad = n; pad < kCellLen; ++pad) w.ch('\0');
	};
	for (const Slot& s : _slots)
	{
		w.ch(static_cast<char>(static_cast<uint8_t>(s.type)));
		w.ch(static_cast<char>(s.enabled ? 1 : 0));
		cell(s.baseUrl.c_str());
		cell(s.clientId.c_str());
		cell(s.routeDn.c_str());
	}
	w.ch(static_cast<char>((_active < kSlots) ? static_cast<uint8_t>(_active) : 0xff));
}

bool TelephonyApiConfig::emitSnapshot(const char* blob, size_t len,
	FunctionRef<bool(const char* key, uint8_t value)> putU8,
	FunctionRef<bool(const char* key, const char* value)> putStr)
{
	// Whole or not at all: the length is exact and every string cell ends in a NUL,
	// so no cell is read past its end and a payload that is not ours stores nothing.
	if (blob == nullptr || len != kSnapshotLen) return false;
	for (size_t i = 0; i < kSlots; ++i)
	{
		for (size_t c = 1; c <= 3; ++c)
		{
			if (blob[i * kSlotSnapshotLen + 2 + c * kCellLen - 1] != '\0') return false;
		}
	}
	char key[16];
	for (size_t i = 0; i < kSlots; ++i)
	{
		const char* p = blob + i * kSlotSnapshotLen;
		slotKey(key, sizeof(key), i, "type");
		if (!putU8(key, static_cast<uint8_t>(p[0]))) return false;
		slotKey(key, sizeof(key), i, "en");
		if (!putU8(key, static_cast<uint8_t>(p[1]))) return false;
		slotKey(key, sizeof(key), i, "url");
		if (!putStr(key, p + 2)) return false;
		slotKey(key, sizeof(key), i, "id");
		if (!putStr(key, p + 2 + kCellLen)) return false;
		slotKey(key, sizeof(key), i, "dn");
		if (!putStr(key, p + 2 + 2 * kCellLen)) return false;
	}
	return putU8("active", static_cast<uint8_t>(blob[kSlots * kSlotSnapshotLen]));
}

std::string TelephonyApiConfig::persist()
{
	// #997: stage everything but the secret, then write the secret if it changed. The
	// snapshot is copied into the NVS writer's slot under the caller's _mutex and the
	// nvs_set_* run on the nvs_writer task. A stage that was refused writes nothing at
	// all, secret included (flash keeps the previous, consistent configuration); the
	// edit is live in RAM either way and a changed secret stays pending.
	const nvswriter::StageResult r = nvswriter::stage(nvswriter::Key::Telephony,
		[this](nvswriter::BlobWriter& w) { fillSnapshot(w); });
	switch (r)
	{
	case nvswriter::StageResult::Ok:
		break;
	case nvswriter::StageResult::Reset:
		return "Telephony config not persisted: a factory reset is running";
	case nvswriter::StageResult::TooBig:
		return "Telephony config not persisted: a field is longer than the writer's cell";
	case nvswriter::StageResult::NotRunning:
		return "Telephony config not persisted: the NVS writer is not running";
	}
	const bool secrets = anySecretPending();
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	const std::string err = secrets ? writeSecretsNow() : std::string();
#else
	// Host: no writer task, and the 0600 file is the one store for everything, written
	// from the table after the stage was accepted. Its secrets go with it.
	const std::string err = writeSecretsNow();
#endif
	if (err.empty() && secrets)
	{
		std::fill(std::begin(_secretPending), std::end(_secretPending), false);
		++_secretWrites;
	}
	return err;
}

// ── Persistence backends ──────────────────────────────────────────────────────

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)

void TelephonyApiConfig::load()
{
	nvswriter::start();   // #997: up before the first persist(); idempotent, host no-op
	std::fill(std::begin(_secretPending), std::end(_secretPending), false);   // RAM == store
	nvs_handle_t h;
	if (nvs_open(kNvsNamespace, NVS_READONLY, &h) != ESP_OK)
	{
		return;  // first boot: defaults stand
	}
	char key[16];
	for (size_t i = 0; i < kSlots; ++i)
	{
		Slot& s = _slots[i];
		uint8_t u8 = 0;
		slotKey(key, sizeof(key), i, "type");
		if (nvs_get_u8(h, key, &u8) == ESP_OK && validProviderByte(u8))
		{
			s.type = static_cast<TelephonyProviderType>(u8);
		}
		u8 = 0;
		slotKey(key, sizeof(key), i, "en");
		if (nvs_get_u8(h, key, &u8) == ESP_OK)
		{
			s.enabled = (u8 != 0);
		}
		// String fields. buf is sized for the largest cap (+NUL) and zeroized
		// after each use so secrets don't linger on the stack.
		char buf[kMaxUrlLen + 1];
		auto getStr = [&](const char* field, std::string& out) {
			slotKey(key, sizeof(key), i, field);
			size_t len = sizeof(buf);
			std::memset(buf, 0, sizeof(buf));
			if (nvs_get_str(h, key, buf, &len) == ESP_OK && buf[0] != '\0')
			{
				out.assign(buf);
			}
			std::memset(buf, 0, sizeof(buf));  // zeroize stack copy
		};
		getStr("url", s.baseUrl);
		getStr("id",  s.clientId);
		getStr("sec", s.secret);
		getStr("dn",  s.routeDn);
		refuseStoredEmergencyRouteDn(s, i);
	}
	uint8_t act = 0xff;
	if (nvs_get_u8(h, "active", &act) == ESP_OK && act < kSlots)
	{
		_active = act;
	}
	nvs_close(h);
}

// The nvs_writer task's half of persist(): every slot's type, enabled flag, URL,
// client id and route DN, then "active", and one commit only if every set worked. The
// secret keys are not touched. `blob` is the writer's internal scratch (the flash
// write must not read PSRAM, #315), never the staging slot.
bool TelephonyApiConfig::writeSnapshot(const char* blob, size_t len)
{
	nvs_handle_t h;
	if (nvs_open(kNvsNamespace, NVS_READWRITE, &h) != ESP_OK)
	{
		return false;
	}
	bool ok = emitSnapshot(blob, len,
		[&h](const char* key, uint8_t value) { return nvs_set_u8(h, key, value) == ESP_OK; },
		[&h](const char* key, const char* value) { return nvs_set_str(h, key, value) == ESP_OK; });
	ok = ok && nvs_commit(h) == ESP_OK;
	nvs_close(h);
	return ok;
}

// The secrets that changed, written here, now, by the caller (under _mutex): one
// nvs_set_str per pending slot, passing the live std::string's c_str() straight in so
// no copy of the secret is made, and one commit. It is a data write, so it is a
// resetguard writer like the nvs_writer task: once a factory reset has begun it writes
// nothing (and leaves the flags set), and the reset's waitForWritersIdle() covers it.
std::string TelephonyApiConfig::writeSecretsNow()
{
	resetguard::WriteScope scope;
	if (!scope.allowed())
	{
		return "Telephony config not persisted: a factory reset is running";
	}
	nvs_handle_t h;
	if (nvs_open(kNvsNamespace, NVS_READWRITE, &h) != ESP_OK)
	{
		return "NVS open failed";
	}
	bool ok = true;
	char key[16];
	for (size_t i = 0; i < kSlots && ok; ++i)
	{
		if (!_secretPending[i]) continue;
		slotKey(key, sizeof(key), i, "sec");
		ok = nvs_set_str(h, key, _slots[i].secret.c_str()) == ESP_OK;
	}
	ok = ok && nvs_commit(h) == ESP_OK;
	nvs_close(h);
	return ok ? "" : "NVS write failed";
}

// The factory reset's erase (clearAll(), its one caller): the whole table, secrets
// included, written here and now, because it runs inside resetguard::begin() where a
// staged write is refused and its caller reports whether the credentials are gone.
std::string TelephonyApiConfig::persistNow()
{
	nvs_handle_t h;
	if (nvs_open(kNvsNamespace, NVS_READWRITE, &h) != ESP_OK)
	{
		return "NVS open failed";
	}
	bool ok = true;
	char key[16];
	for (size_t i = 0; i < kSlots && ok; ++i)
	{
		const Slot& s = _slots[i];
		slotKey(key, sizeof(key), i, "type");
		ok = ok && nvs_set_u8(h, key, static_cast<uint8_t>(s.type)) == ESP_OK;
		slotKey(key, sizeof(key), i, "en");
		ok = ok && nvs_set_u8(h, key, s.enabled ? 1 : 0) == ESP_OK;
		slotKey(key, sizeof(key), i, "url");
		ok = ok && nvs_set_str(h, key, s.baseUrl.c_str()) == ESP_OK;
		slotKey(key, sizeof(key), i, "id");
		ok = ok && nvs_set_str(h, key, s.clientId.c_str()) == ESP_OK;
		slotKey(key, sizeof(key), i, "sec");
		ok = ok && nvs_set_str(h, key, s.secret.c_str()) == ESP_OK;
		slotKey(key, sizeof(key), i, "dn");
		ok = ok && nvs_set_str(h, key, s.routeDn.c_str()) == ESP_OK;
	}
	ok = ok && nvs_set_u8(h, "active",
	          (_active < kSlots) ? static_cast<uint8_t>(_active) : 0xff) == ESP_OK;
	ok = ok && nvs_commit(h) == ESP_OK;
	nvs_close(h);
	return ok ? "" : "NVS write failed";
}

#else  // host builds: 0600-permission key=value file

void TelephonyApiConfig::load()
{
	nvswriter::start();   // #997: up before the first persist(); idempotent, host no-op
	std::fill(std::begin(_secretPending), std::end(_secretPending), false);   // RAM == store
	std::ifstream f(_storePath);
	if (!f.is_open())
	{
		return;  // no store yet: defaults stand
	}
	std::string line;
	while (std::getline(f, line))
	{
		const size_t eq = line.find('=');
		if (eq == std::string::npos || eq < 3)
		{
			continue;
		}
		const std::string k = line.substr(0, eq);
		const std::string val = line.substr(eq + 1);
		if (k == "active")
		{
			const long a = std::strtol(val.c_str(), nullptr, 10);
			if (a >= 0 && static_cast<size_t>(a) < kSlots) _active = static_cast<size_t>(a);
			continue;
		}
		if (k[0] != 's' || k[1] < '0' || k[1] >= '0' + static_cast<char>(kSlots))
		{
			continue;
		}
		Slot& s = _slots[static_cast<size_t>(k[1] - '0')];
		const std::string field = k.substr(2);
		if (field == "type")
		{
			const long t = std::strtol(val.c_str(), nullptr, 10);
			if (t >= 0 && validProviderByte(static_cast<uint8_t>(t)))
				s.type = static_cast<TelephonyProviderType>(t);
		}
		else if (field == "en")  s.enabled = (val == "1");
		else if (field == "url") s.baseUrl = val;
		else if (field == "id")  s.clientId = val;
		else if (field == "sec") s.secret = val;
		else if (field == "dn")  s.routeDn = val;
	}
	for (size_t i = 0; i < kSlots; ++i)
	{
		refuseStoredEmergencyRouteDn(_slots[i], i);
	}
}

// Host: there is one file, so "write the secrets" is "write the file" (the secrets are
// in it). persist() calls this after every accepted stage, so the file always carries
// the whole table; the pending flags (and the secretWrites() count) are what say
// whether a secret was part of that write.
std::string TelephonyApiConfig::writeSecretsNow()
{
	return persistNow();
}

std::string TelephonyApiConfig::persistNow()
{
#if defined(_WIN32)
	// No POSIX permission model; honest in-memory only (the file would be
	// world-readable). The table still works for the session.
	return "";
#else
	// Create/truncate with 0600 BEFORE any secret byte hits the disk.
	const int fd = ::open(_storePath.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0)
	{
		return "config file open failed";
	}
	// In case the file pre-existed with looser bits.
	(void)::fchmod(fd, 0600);

	std::ostringstream out;
	for (size_t i = 0; i < kSlots; ++i)
	{
		const Slot& s = _slots[i];
		out << 's' << i << "type=" << static_cast<int>(s.type) << '\n'
		    << 's' << i << "en="   << (s.enabled ? 1 : 0) << '\n'
		    << 's' << i << "url="  << s.baseUrl << '\n'
		    << 's' << i << "id="   << s.clientId << '\n'
		    << 's' << i << "sec="  << s.secret << '\n'
		    << 's' << i << "dn="   << s.routeDn << '\n';
	}
	if (_active < kSlots)
	{
		out << "active=" << _active << '\n';
	}
	std::string data = out.str();
	const bool ok = ::write(fd, data.data(), data.size()) ==
	                static_cast<ssize_t>(data.size());
	::close(fd);
	std::fill(data.begin(), data.end(), '\0');  // scrub the serialized copy
	return ok ? "" : "config file write failed";
#endif
}

#endif
