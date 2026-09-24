// SipSecretStore.cpp — per-extension SIP digest credential store.
//
// See SipSecretStore.hpp for the design rationale and the HA1-at-rest security
// note. Persistence mirrors AdminAuth (nvs_open/nvs_set_str/nvs_commit, in the
// namespace "sipauth"); on host an in-memory map IS the store.

#include "SipSecretStore.hpp"
#include "SipDigest.hpp"

#include <map>
#include <mutex>
#include <cctype>
#include <algorithm>

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	#include "nvs_flash.h"
	#include "nvs.h"
	#include "esp_random.h"   // esp_random() — hardware CSPRNG (RF subsystem active)
#else
	#include <random>         // std::random_device — host CSPRNG
#endif

namespace
{
	constexpr const char* kNamespace = "sipauth";
	constexpr const char* kKeyPrefix = "ext_";       // "ext_" + ext, ≤ 15 chars
	constexpr const char* kIndexKey  = "idx";        // newline-separated ext list

	std::mutex& storeMutex()
	{
		static std::mutex m;
		return m;
	}

	// An extension is a SIP AOR user part. Permit a conservative, NVS-key-safe set
	// (digits, letters, and the handful of RFC 3261 "user" marks we actually use).
	// Reject anything that would make an unsafe NVS key or an injectable index line.
	bool isValidExt(const std::string& ext)
	{
		if (ext.empty() || ext.size() > SipSecretStore::kMaxExtLen)
		{
			return false;
		}
		for (char c : ext)
		{
			unsigned char u = static_cast<unsigned char>(c);
			bool ok = std::isalnum(u) || c == '.' || c == '-' || c == '_';
			if (!ok)
			{
				return false;
			}
		}
		return true;
	}

	std::string nvsKeyFor(const std::string& ext)
	{
		// "ext_" (4) + ext (≤ 11) = ≤ 15, the NVS key cap. isValidExt() guarantees
		// the bound, so no hashing/truncation is needed for the supported AOR space.
		return std::string(kKeyPrefix) + ext;
	}

#if !(defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO))
	// --- Host-side in-memory mirror (also the store on host) ---
	// Host-only: every caller is a host #else arm, so defining it on ESP was an
	// unused function (-Wunused-function; BigDog's ESP build of #437).
	std::map<std::string, std::string>& hostMap()
	{
		static std::map<std::string, std::string> m;
		return m;
	}
#endif

	// --- CSPRNG secret generation (single audited entropy source) ---
	// Unambiguous alphabet: no 0/O/1/I/l, 54 symbols, ~5.755 bits/char.
	constexpr char kSecretAlphabet[] =
		"ABCDEFGHJKLMNPQRSTUVWXYZ23456789abcdefghijkmnpqrstuvwxyz";
	constexpr int kSecretAlphabetLen = (int)sizeof(kSecretAlphabet) - 1;   // 54

	// One CSPRNG byte. esp_random() is the hardware RNG (CSPRNG-grade while the RF
	// subsystem is up, which it always is here); std::random_device is the host's
	// non-deterministic source. Both are uniform over 0..255.
	unsigned char csprngByte()
	{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
		return (unsigned char)(esp_random() & 0xFFu);
#else
		static thread_local std::random_device rd;
		std::uniform_int_distribution<unsigned int> d(0, 255);
		return (unsigned char)d(rd);
#endif
	}

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	// In-RAM HA1 cache (ESP only — on host hostMap() already lives in RAM). Keeps
	// steady-state Secure REGISTERs off the flash path: getHa1() reads NVS at most
	// once per extension per boot, then serves from RAM. Coherent with set/clear.
	// Guarded by storeMutex() (same lock as every other accessor here).
	std::map<std::string, std::string>& ha1Cache()
	{
		static std::map<std::string, std::string> m;
		return m;
	}
#endif

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	// --- Index maintenance (ESP): a newline-separated set of secured extensions,
	// stored under kIndexKey so securedExtensions() needs no NVS enumeration. ---

	std::vector<std::string> readIndexLocked(nvs_handle_t h)
	{
		std::vector<std::string> out;
		size_t len = 0;
		if (nvs_get_str(h, kIndexKey, nullptr, &len) != ESP_OK || len == 0)
		{
			return out;
		}
		std::string buf(len, '\0');
		if (nvs_get_str(h, kIndexKey, buf.data(), &len) != ESP_OK)
		{
			return out;
		}
		// len includes the trailing NUL; trim it to get the stored text.
		if (len > 0) buf.resize(len - 1);
		std::string s = std::move(buf);
		size_t start = 0;
		while (start < s.size())
		{
			size_t nl = s.find('\n', start);
			std::string tok = (nl == std::string::npos) ? s.substr(start)
			                                             : s.substr(start, nl - start);
			if (!tok.empty()) out.push_back(tok);
			if (nl == std::string::npos) break;
			start = nl + 1;
		}
		return out;
	}

	bool writeIndexLocked(nvs_handle_t h, const std::vector<std::string>& exts)
	{
		std::string joined;
		for (const auto& e : exts)
		{
			joined += e;
			joined += '\n';
		}
		return nvs_set_str(h, kIndexKey, joined.c_str()) == ESP_OK;
	}

	void indexAddLocked(nvs_handle_t h, const std::string& ext)
	{
		auto exts = readIndexLocked(h);
		if (std::find(exts.begin(), exts.end(), ext) == exts.end())
		{
			exts.push_back(ext);
			writeIndexLocked(h, exts);
		}
	}

	void indexRemoveLocked(nvs_handle_t h, const std::string& ext)
	{
		auto exts = readIndexLocked(h);
		auto it = std::remove(exts.begin(), exts.end(), ext);
		if (it != exts.end())
		{
			exts.erase(it, exts.end());
			writeIndexLocked(h, exts);
		}
	}
#endif
}

namespace SipSecretStore
{
	bool setSecret(const std::string& ext, const std::string& plaintextSecret)
	{
		if (!isValidExt(ext) || plaintextSecret.empty())
		{
			return false;
		}

		std::string ha1 = SipDigest::computeHa1(ext, kRealm, plaintextSecret);

		std::lock_guard<std::mutex> lock(storeMutex());

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
		nvs_handle_t h;
		if (nvs_open(kNamespace, NVS_READWRITE, &h) != ESP_OK)
		{
			return false;
		}
		bool ok = (nvs_set_str(h, nvsKeyFor(ext).c_str(), ha1.c_str()) == ESP_OK);
		if (ok)
		{
			indexAddLocked(h, ext);
			ok = (nvs_commit(h) == ESP_OK);
		}
		nvs_close(h);
		if (ok)
		{
			ha1Cache()[ext] = ha1;   // keep the RAM cache coherent with NVS
		}
		return ok;
#else
		hostMap()[ext] = ha1;
		return true;
#endif
	}

	std::string makeRandomSecret(int len)
	{
		if (len <= 0)
		{
			return std::string();
		}
		// Rejection sampling: accept only bytes in the largest multiple of the
		// alphabet size that fits in [0,256), so every symbol is equiprobable.
		const int n = kSecretAlphabetLen;
		const int limit = 256 - (256 % n);   // 216 for n=54 → reject 216..255
		std::string out;
		out.reserve((size_t)len);
		while ((int)out.size() < len)
		{
			unsigned char b = csprngByte();
			if (b >= (unsigned char)limit)
			{
				continue;            // biased tail — draw again
			}
			out.push_back(kSecretAlphabet[b % n]);
		}
		return out;
	}

	std::optional<std::string> generateSecret(const std::string& ext)
	{
		if (!isValidExt(ext))
		{
			return std::nullopt;
		}
		std::string secret = makeRandomSecret(kGeneratedSecretLen);
		if (secret.empty() || !setSecret(ext, secret))
		{
			return std::nullopt;
		}
		return secret;
	}

	void warmCache()
	{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
		// securedExtensions() and getHa1() each take storeMutex() internally and
		// release before the next call returns, so calling them in sequence here is
		// safe (std::mutex is non-recursive). getHa1() populates ha1Cache() as a
		// side effect, so this leaves every secured extension warm in RAM.
		for (const auto& ext : securedExtensions())
		{
			(void)getHa1(ext);
		}
#endif
	}

	std::optional<std::string> getHa1(const std::string& ext)
	{
		if (!isValidExt(ext))
		{
			return std::nullopt;
		}

		std::lock_guard<std::mutex> lock(storeMutex());

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
		// RAM cache first — the hot path (a secured phone re-REGISTERing) never
		// touches flash after the first lookup for that extension.
		{
			auto cit = ha1Cache().find(ext);
			if (cit != ha1Cache().end())
			{
				return cit->second;
			}
		}
		nvs_handle_t h;
		if (nvs_open(kNamespace, NVS_READONLY, &h) != ESP_OK)
		{
			return std::nullopt;
		}
		char buf[64] = {0};
		size_t len = sizeof(buf);
		esp_err_t err = nvs_get_str(h, nvsKeyFor(ext).c_str(), buf, &len);
		nvs_close(h);
		if (err == ESP_OK && buf[0] != '\0')
		{
			ha1Cache()[ext] = buf;   // warm the cache for subsequent REGISTERs
			return std::string(buf);
		}
		return std::nullopt;
#else
		auto it = hostMap().find(ext);
		if (it != hostMap().end())
		{
			return it->second;
		}
		return std::nullopt;
#endif
	}

	bool hasSecret(const std::string& ext)
	{
		return getHa1(ext).has_value();
	}

	bool clearSecret(const std::string& ext)
	{
		if (!isValidExt(ext))
		{
			return false;
		}

		std::lock_guard<std::mutex> lock(storeMutex());

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
		nvs_handle_t h;
		if (nvs_open(kNamespace, NVS_READWRITE, &h) != ESP_OK)
		{
			return false;
		}
		esp_err_t err = nvs_erase_key(h, nvsKeyFor(ext).c_str());
		// ESP_ERR_NVS_NOT_FOUND is benign (nothing to clear).
		bool ok = (err == ESP_OK || err == ESP_ERR_NVS_NOT_FOUND);
		if (ok)
		{
			indexRemoveLocked(h, ext);
			ok = (nvs_commit(h) == ESP_OK);
		}
		nvs_close(h);
		ha1Cache().erase(ext);   // drop the RAM copy so a stale HA1 can't authenticate
		return ok;
#else
		hostMap().erase(ext);
		return true;
#endif
	}

	bool clearAll()
	{
		std::lock_guard<std::mutex> lock(storeMutex());

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
		// "sipauth" holds nothing but these secrets and their index, so a
		// namespace wipe is exact -- and unlike walking the index it also catches
		// an ext_* key the index lost track of (an interrupted setSecret()).
		nvs_handle_t h;
		esp_err_t err = nvs_open(kNamespace, NVS_READWRITE, &h);
		if (err == ESP_ERR_NVS_NOT_FOUND)
		{
			ha1Cache().clear();
			return true;   // never written: nothing to clear
		}
		if (err != ESP_OK)
		{
			return false;
		}
		bool ok = (nvs_erase_all(h) == ESP_OK) && (nvs_commit(h) == ESP_OK);
		nvs_close(h);
		ha1Cache().clear();   // a cached HA1 must not keep authenticating
		return ok;
#else
		hostMap().clear();
		return true;
#endif
	}

	std::vector<std::string> securedExtensions()
	{
		std::lock_guard<std::mutex> lock(storeMutex());

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
		nvs_handle_t h;
		if (nvs_open(kNamespace, NVS_READONLY, &h) != ESP_OK)
		{
			return {};
		}
		auto out = readIndexLocked(h);
		nvs_close(h);
		return out;
#else
		std::vector<std::string> out;
		out.reserve(hostMap().size());
		for (const auto& kv : hostMap())
		{
			out.push_back(kv.first);
		}
		return out;
#endif
	}
}
