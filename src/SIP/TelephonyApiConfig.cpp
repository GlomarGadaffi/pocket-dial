#include "TelephonyApiConfig.hpp"

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <algorithm>

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	// Persisted in a DEDICATED NVS namespace ("tapicfg") so a factory-reset of
	// the PBX config ("pbxcfg") never collaterally wipes — or accidentally
	// dumps — API credentials. NOTE: values are plaintext in flash unless the
	// device enables flash encryption + NVS encryption; see the header's
	// secret-handling model.
	#include "nvs_flash.h"
	#include "nvs.h"
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
	if (s.enabled)
	{
		// An ENABLED slot must be dialable: real provider, https endpoint.
		if (s.type != TelephonyProviderType::Loopback &&
		    s.baseUrl.rfind("https://", 0) != 0)
		{
			return "Enabled slot needs an https:// base URL";
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
		scrub(dst.secret);
		dst.secret = s.secret;
	}
	return persist();
}

std::string TelephonyApiConfig::clearSlot(size_t idx)
{
	if (idx >= kSlots)
	{
		return "Bad slot index";
	}
	Slot& s = _slots[idx];
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
	return persist();
}

std::string TelephonyApiConfig::clearAll()
{
	// Reuse clearSlot() itself (zeroize + persist + clear-active-if-needed)
	// across every slot rather than duplicating its logic -- see this
	// method's header comment. Keep going even if one slot's persist fails,
	// so a factory reset always zeroizes every slot's in-memory secret;
	// report the last error, if any.
	std::string lastErr;
	for (size_t i = 0; i < kSlots; ++i)
	{
		const std::string err = clearSlot(i);
		if (!err.empty())
		{
			lastErr = err;
		}
	}
	return lastErr;
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

// ── Persistence backends ──────────────────────────────────────────────────────

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)

void TelephonyApiConfig::load()
{
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
	}
	uint8_t act = 0xff;
	if (nvs_get_u8(h, "active", &act) == ESP_OK && act < kSlots)
	{
		_active = act;
	}
	nvs_close(h);
}

std::string TelephonyApiConfig::persist()
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
}

std::string TelephonyApiConfig::persist()
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
