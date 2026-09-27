#include "EmailConfigStore.hpp"

#include <mutex>

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	#include "nvs_flash.h"
	#include "nvs.h"
#endif

namespace EmailConfigStore
{

namespace
{
	constexpr const char* kNvsNamespace = "pbxcfg"; // shared PBX config namespace (see PbxPersist.hpp)

	std::mutex g_mutex;
	Config g_cache;
	bool g_loaded = false;

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)

	// nvs_get_str into a std::string, growing the buffer to whatever NVS
	// reports as the stored length. Leaves `out` untouched if the key is
	// absent -- Config{}'s default then stands, same convention as
	// AdminAuth/DeviceConfig.
	void readStr(nvs_handle_t h, const char* key, std::string& out)
	{
		size_t len = 0;
		if (nvs_get_str(h, key, nullptr, &len) != ESP_OK || len == 0) return;
		std::string buf(len, '\0');
		if (nvs_get_str(h, key, buf.data(), &len) == ESP_OK)
		{
			// len includes the NUL terminator on return.
			buf.resize(len > 0 ? len - 1 : 0);
			out = std::move(buf);
		}
	}

	void readBlob(nvs_handle_t h, const char* key, std::string& out)
	{
		size_t len = 0;
		if (nvs_get_blob(h, key, nullptr, &len) != ESP_OK || len == 0) return;
		std::string buf(len, '\0');
		if (nvs_get_blob(h, key, buf.data(), &len) == ESP_OK)
		{
			buf.resize(len);
			out = std::move(buf);
		}
	}

	Config loadFromNvs()
	{
		Config cfg; // defaults stand for anything absent/corrupt
		nvs_handle_t h;
		if (nvs_open(kNvsNamespace, NVS_READONLY, &h) != ESP_OK)
		{
			return cfg;
		}

		readStr(h, "smtp_host", cfg.host);
		uint16_t port = cfg.port;
		if (nvs_get_u16(h, "smtp_port", &port) == ESP_OK) cfg.port = port;
		readStr(h, "smtp_mode", cfg.mode);
		readStr(h, "smtp_auth", cfg.auth);
		readStr(h, "smtp_user", cfg.user);
		readStr(h, "smtp_pass", cfg.pass);
		readStr(h, "smtp_from", cfg.from);
		readStr(h, "smtp_to", cfg.to);
		readStr(h, "gsa_email", cfg.gsaEmail);
		readBlob(h, "gsa_key", cfg.gsaKey);
		uint8_t insecure = cfg.insecureSkipVerify ? 1 : 0;
		if (nvs_get_u8(h, "smtp_insecure", &insecure) == ESP_OK) cfg.insecureSkipVerify = (insecure != 0);
		readBlob(h, "smtp_ca_pem", cfg.caPem);

		nvs_close(h);
		return cfg;
	}

	bool saveToNvs(const Config& cfg)
	{
		nvs_handle_t h;
		if (nvs_open(kNvsNamespace, NVS_READWRITE, &h) != ESP_OK)
		{
			return false;
		}
		bool ok = true;
		ok = ok && nvs_set_str(h, "smtp_host", cfg.host.c_str()) == ESP_OK;
		ok = ok && nvs_set_u16(h, "smtp_port", cfg.port) == ESP_OK;
		ok = ok && nvs_set_str(h, "smtp_mode", cfg.mode.c_str()) == ESP_OK;
		ok = ok && nvs_set_str(h, "smtp_auth", cfg.auth.c_str()) == ESP_OK;
		ok = ok && nvs_set_str(h, "smtp_user", cfg.user.c_str()) == ESP_OK;
		ok = ok && nvs_set_str(h, "smtp_pass", cfg.pass.c_str()) == ESP_OK;
		ok = ok && nvs_set_str(h, "smtp_from", cfg.from.c_str()) == ESP_OK;
		ok = ok && nvs_set_str(h, "smtp_to", cfg.to.c_str()) == ESP_OK;
		ok = ok && nvs_set_str(h, "gsa_email", cfg.gsaEmail.c_str()) == ESP_OK;
		ok = ok && nvs_set_blob(h, "gsa_key", cfg.gsaKey.data(), cfg.gsaKey.size()) == ESP_OK;
		ok = ok && nvs_set_u8(h, "smtp_insecure", cfg.insecureSkipVerify ? 1 : 0) == ESP_OK;
		ok = ok && nvs_set_blob(h, "smtp_ca_pem", cfg.caPem.data(), cfg.caPem.size()) == ESP_OK;
		ok = ok && nvs_commit(h) == ESP_OK;
		nvs_close(h);
		return ok;
	}

#endif // ESP_PLATFORM
} // namespace

Config load()
{
	std::lock_guard<std::mutex> lk(g_mutex);
	if (!g_loaded)
	{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
		g_cache = loadFromNvs();
#endif
		// Host: g_cache starts at Config{}'s defaults and IS the store --
		// nothing else to load, same convention as AdminAuth's AuthState.
		g_loaded = true;
	}
	return g_cache;
}

bool save(const Config& cfg)
{
	std::lock_guard<std::mutex> lk(g_mutex);
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	if (!saveToNvs(cfg))
	{
		return false;
	}
#endif
	g_cache = cfg;
	g_loaded = true;
	return true;
}

bool clear()
{
	std::lock_guard<std::mutex> lk(g_mutex);
	bool ok = true;
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	// ERASE every key rather than save(Config{}): writing empty values relies on
	// a zero-length nvs_set_blob succeeding for gsa_key/smtp_ca_pem, and save()'s
	// chain stops at the first failure -- leaving the private key behind. An
	// erase has no such dependency; NOT_FOUND (never set) is success. (#363,
	// raised by Globox in review.)
	static const char* const kKeys[] = {
		"smtp_host", "smtp_port", "smtp_mode", "smtp_auth", "smtp_user", "smtp_pass",
		"smtp_from", "smtp_to", "gsa_email", "gsa_key", "smtp_insecure", "smtp_ca_pem",
	};
	nvs_handle_t h;
	esp_err_t err = nvs_open(kNvsNamespace, NVS_READWRITE, &h);
	if (err == ESP_OK)
	{
		for (const char* key : kKeys)   // every key attempted, even after a failure
		{
			const esp_err_t e = nvs_erase_key(h, key);
			if (e != ESP_OK && e != ESP_ERR_NVS_NOT_FOUND) ok = false;
		}
		if (nvs_commit(h) != ESP_OK) ok = false;
		nvs_close(h);
	}
	else if (err != ESP_ERR_NVS_NOT_FOUND)
	{
		ok = false;
	}
#endif
	g_cache = Config{};
	g_loaded = true;
	return ok;
}

#if !defined(ESP_PLATFORM) && !defined(ESP32) && !defined(ARDUINO)
void resetForTest()
{
	std::lock_guard<std::mutex> lk(g_mutex);
	g_cache = Config{};
	g_loaded = false;
}
#endif

} // namespace EmailConfigStore
