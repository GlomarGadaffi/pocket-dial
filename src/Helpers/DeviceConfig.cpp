// DeviceConfig.cpp: SoftAP security settings + the flash-time configuration seed.
//
// See DeviceConfig.hpp for the design rationale and the authoritative 256-byte
// `cfgseed` wire format. This file is intentionally dependency-free beyond the
// C++17 standard library and the platform guards — the SAME translation unit
// compiles into the host test suite, where there is no NVS and no partition
// table, so the ~289-test dashboard suite can exercise the same code paths.
//
// Deliberately NOT included here: esp_wifi.h. The pure-Ethernet transports
// ("eth", "lan8720") are built WITHOUT POCKETDIAL_HAS_WIFI and still link this
// file — they need applyFlashSeed() so `wifi_mode` and future seed fields are
// honoured — so a WiFi dependency here would break those builds outright. The
// only ESP components touched are nvs, esp_random and esp_partition, all of
// which exist on every transport.
//
// Randomness: esp_random() (a hardware CSPRNG) on ESP; on host, a
// std::random_device-seeded std::mt19937_64 — the same split AdminAuth.cpp
// makes, for the same reason (host is a developer/CI simulator, not the
// production trust boundary — see docs/THREAT_MODEL.md).

#include "DeviceConfig.hpp"

#include <array>
#include <atomic>
#include <mutex>
#include <cstring>
#include <chrono>

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	// On the device, settings persist in NVS, randomness comes from the hardware
	// RNG, and the seed is read out of a raw data partition. nvs_flash/nvs/
	// esp_random/esp_partition are core ESP-IDF components present on EVERY
	// transport (wifi, eth, lan8720, display) — they are not WiFi-specific, so
	// they must be gated on ESP_PLATFORM, not POCKETDIAL_HAS_WIFI.
	#include "nvs_flash.h"
	#include "nvs.h"
	#include "esp_random.h"
	#include "esp_partition.h"
	// esp_log is in the same class as the three above: a core component present
	// on every transport, not a WiFi dependency. The schema-version banner is
	// emitted HERE rather than in the four main/esp_main*.cpp entry points so
	// that the one message an operator has to see on a downgrade cannot drift
	// between transports or be forgotten by a fifth entry point later.
	#include "esp_log.h"
#else
	#include <random>
#endif

namespace
{
	// NVS namespace + keys. Shared with AdminAuth and the transports; the three
	// keys below are the complete set clearAll() (i.e. /api/factory-reset) drops.
	constexpr const char* kNvsNamespace = "storage";
	constexpr const char* kKeyApSecure  = "ap_secure";
	constexpr const char* kKeyApPsk     = "ap_psk";
	constexpr const char* kKeySeedGen   = "cfgseed_gen";
	// Owned by Registrar (src/SIP/Registrar.cpp reads it); written here from the
	// flash seed and cleared here by factory reset. Kept as a literal rather than
	// an include so DeviceConfig stays free of any src/SIP dependency.
	constexpr const char* kKeyRegMode   = "reg_mode";

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	// reg_mode is the ONE key this file touches that lives in a different NVS
	// namespace from everything else here: Registrar owns it in `pbxcfg`, while
	// every other DeviceConfig field is in `storage`. That single exception has
	// now caused the same bug twice — each call site did its own nvs_open and
	// each had to remember the exception independently:
	//
	//   #151 (fixed v1.4.1) — applyFlashSeed() WROTE it to `storage`, so the
	//        flash-time registrar mode was committed somewhere the registrar
	//        never looks. Shipped inert in two releases.
	//   #188 (fixed here)   — clearAll() ERASED it from `storage`, so a factory
	//        reset could not clear the mode. That broke the documented rescue for
	//        a board flipped to `secure` before any extension was adopted, which
	//        rejects every REGISTER and locks the operator out; the comment in
	//        clearAll() says that rescue is the entire reason the erase exists.
	//
	// #151's fix added kRegistrarNvsNamespace and a static_assert tying it to
	// pbxpersist::kNvsNamespace — but a static_assert can only prove the CONSTANT
	// is right, never that a call site uses it, which is exactly how clearAll()
	// slipped through. So both accesses now go through these two helpers and the
	// namespace is named in one place. Do not open pbxcfg inline again.
	bool writeRegistrarMode(uint8_t mode)
	{
		nvs_handle_t rh;
		if (nvs_open(DeviceConfig::kRegistrarNvsNamespace, NVS_READWRITE, &rh) != ESP_OK)
		{
			return false;
		}
		bool ok = (nvs_set_u8(rh, kKeyRegMode, mode) == ESP_OK);
		if (ok)
		{
			ok = (nvs_commit(rh) == ESP_OK);
		}
		nvs_close(rh);
		return ok;
	}

	// Drop the persisted mode so the next boot falls back to the compiled-in
	// default. Absent key is success: nothing to clear is the desired end state.
	void eraseRegistrarMode()
	{
		nvs_handle_t rh;
		if (nvs_open(DeviceConfig::kRegistrarNvsNamespace, NVS_READWRITE, &rh) != ESP_OK)
		{
			return;
		}
		nvs_erase_key(rh, kKeyRegMode);   // ESP_ERR_NVS_NOT_FOUND is fine
		nvs_commit(rh);
		nvs_close(rh);
	}
#endif

	// Alphabet size, computed rather than written as a literal: the modulo-bias
	// rejection threshold below depends on it, and a hand-copied constant that
	// drifts from kPskAlphabet would silently reintroduce the bias.
	constexpr size_t alphabetLen()
	{
		size_t n = 0;
		while (DeviceConfig::kPskAlphabet[n] != '\0')
		{
			++n;
		}
		return n;
	}

	// ---------------------------------------------------------------------
	// CRC-32, IEEE 802.3 / zlib: reflected polynomial 0xEDB88320, init
	// 0xFFFFFFFF, final xor 0xFFFFFFFF.
	//
	// Nibble-at-a-time with a 16-entry table: 64 bytes of .rodata instead of the
	// usual 1 KB byte-wide table, and no runtime table generation. Speed is
	// irrelevant — this runs once, over 252 bytes, at boot.
	//
	// THIS MUST AGREE BYTE FOR BYTE with the JavaScript CRC in
	// docs/flasher/index.html: it is the only integrity check standing between a
	// half-written or erased `cfgseed` partition and a device that silently
	// applies garbage WiFi credentials to itself. Sanity vector:
	// crc32("123456789") == 0xCBF43926.
	//
	// [[maybe_unused]] here and on the three seed decoders below: only
	// applyFlashSeed()'s device branch calls them, but they are deliberately kept
	// OUTSIDE the platform guard so the host compiler still type-checks the wire
	// decoding on every CI run. Without the attribute that costs a
	// -Wunused-function warning on the host build.
	// ---------------------------------------------------------------------
	[[maybe_unused]] uint32_t crc32Ieee(const uint8_t* data, size_t len)
	{
		static const uint32_t kNibbleTable[16] = {
			0x00000000u, 0x1DB71064u, 0x3B6E20C8u, 0x26D930ACu,
			0x76DC4190u, 0x6B6B51F4u, 0x4DB26158u, 0x5005713Cu,
			0xEDB88320u, 0xF00F9344u, 0xD6D6A3E8u, 0xCB61B38Cu,
			0x9B64C2B0u, 0x86D3D2D4u, 0xA00AE278u, 0xBDBDF21Cu
		};

		uint32_t crc = 0xFFFFFFFFu;
		for (size_t i = 0; i < len; ++i)
		{
			crc ^= data[i];
			crc = (crc >> 4) ^ kNibbleTable[crc & 0x0Fu];
			crc = (crc >> 4) ^ kNibbleTable[crc & 0x0Fu];
		}
		return crc ^ 0xFFFFFFFFu;
	}

	// Cryptographically-strong (on ESP) random bytes. On host, a PRNG seeded
	// from std::random_device — adequate for the host simulator. Lifted from
	// AdminAuth.cpp so both modules draw from the same source on each platform.
	void fillRandom(uint8_t* buf, size_t len)
	{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
		// Hardware CSPRNG, available on every ESP transport.
		for (size_t i = 0; i < len; ++i)
		{
			buf[i] = static_cast<uint8_t>(esp_random() & 0xFF);
		}
#else
		static std::mt19937_64 rng = [] {
			std::random_device rd;
			uint64_t seed = (static_cast<uint64_t>(rd()) << 32) ^ rd();
			seed ^= static_cast<uint64_t>(
				std::chrono::steady_clock::now().time_since_epoch().count());
			return std::mt19937_64(seed);
		}();
		for (size_t i = 0; i < len; ++i)
		{
			buf[i] = static_cast<uint8_t>(rng() & 0xFF);
		}
#endif
	}

	// A fresh kGeneratedPskChars-character passphrase over kPskAlphabet.
	//
	// Rejection sampling, NOT `byte % 30`: the alphabet has 30 symbols and 256 is
	// not a multiple of 30, so a plain modulo would make the first 16 symbols
	// (256 - 240) noticeably likelier than the last 14 and quietly shave entropy
	// off every generated passphrase. Drawing a byte and discarding anything at
	// or above 240 (the largest multiple of 30 that fits in a byte) makes the
	// distribution exactly uniform. The expected number of rejections is tiny
	// (16/256 per draw), and rejected bytes are simply refilled.
	std::string generatePsk()
	{
		constexpr size_t kAlpha = alphabetLen();
		constexpr uint8_t kLimit =
			static_cast<uint8_t>((256u / kAlpha) * kAlpha);   // 240 for 30 symbols

		std::string out;
		out.reserve(DeviceConfig::kGeneratedPskChars);
		while (out.size() < DeviceConfig::kGeneratedPskChars)
		{
			// Refill in blocks so the CSPRNG is called in bulk rather than once
			// per accepted character.
			std::array<uint8_t, 32> block{};
			fillRandom(block.data(), block.size());
			for (size_t i = 0; i < block.size() && out.size() < DeviceConfig::kGeneratedPskChars; ++i)
			{
				if (block[i] >= kLimit)
				{
					continue;   // biased tail — redraw rather than fold it in
				}
				out.push_back(DeviceConfig::kPskAlphabet[block[i] % kAlpha]);
			}
		}
		return out;
	}

	// A passphrase esp_wifi will actually accept: IEEE 802.11i length bounds and
	// printable ASCII only. Enforced on BOTH the dashboard path (setApPsk) and
	// the seed path, so a malformed seed can never install a passphrase that
	// bricks the AP at the next bringup.
	bool isValidPsk(const std::string& psk)
	{
		if (psk.size() < DeviceConfig::kMinPskChars || psk.size() > DeviceConfig::kMaxPskChars)
		{
			return false;
		}
		for (char c : psk)
		{
			unsigned char u = static_cast<unsigned char>(c);
			if (u < 0x20 || u > 0x7E)
			{
				return false;
			}
		}
		return true;
	}

	// ---------------------------------------------------------------------
	// Shared, mutex-guarded state.
	// ---------------------------------------------------------------------
	struct ConfigState
	{
		std::mutex mutex;

		// In-memory mirror of the stored settings. On ESP this is loaded from NVS
		// on first access; on host it IS the store (host has no NVS), which is why
		// `apPsk` persists for exactly one process lifetime there.
		bool        loaded = false;     // have we tried to load from NVS yet?
		bool        apSecure = false;   // DEFAULTS FALSE — see DeviceConfig.hpp
		std::string apPsk;              // empty until generated on first access
	};

	// Function-local static: avoids a static-initialization-order fiasco and is
	// thread-safe to initialize under C++11+.
	ConfigState& state()
	{
		static ConfigState s;
		return s;
	}

	// --- NVS-backed persistence (ESP only); no-ops on host. ---
	// Caller must hold state().mutex.
	void loadLocked(ConfigState& s)
	{
		if (s.loaded)
		{
			return;
		}
		s.loaded = true;

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
		nvs_handle_t h;
		if (nvs_open(kNvsNamespace, NVS_READWRITE, &h) == ESP_OK)
		{
			uint8_t secure = 0;
			if (nvs_get_u8(h, kKeyApSecure, &secure) == ESP_OK)
			{
				s.apSecure = (secure != 0);
			}

			// 128 bytes covers the 63-char WPA2 maximum with room to spare; a
			// stored value longer than the buffer returns ESP_ERR_NVS_INVALID_LENGTH
			// and is treated as absent, which regenerates rather than truncates.
			char pskBuf[128] = {0};
			size_t pskLen = sizeof(pskBuf);
			if (nvs_get_str(h, kKeyApPsk, pskBuf, &pskLen) == ESP_OK && pskBuf[0] != '\0')
			{
				s.apPsk = pskBuf;
			}
			nvs_close(h);
		}
#else
		(void)s;
#endif
	}

	// Caller must hold state().mutex.
	bool persistApSecureLocked(bool secure)
	{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
		nvs_handle_t h;
		if (nvs_open(kNvsNamespace, NVS_READWRITE, &h) != ESP_OK)
		{
			return false;
		}
		bool ok = (nvs_set_u8(h, kKeyApSecure, secure ? 1 : 0) == ESP_OK) &&
		          (nvs_commit(h) == ESP_OK);
		nvs_close(h);
		return ok;
#else
		// Host: the in-memory ConfigState IS the store. Nothing else to do.
		(void)secure;
		return true;
#endif
	}

	// Caller must hold state().mutex.
	bool persistApPskLocked(const std::string& psk)
	{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
		nvs_handle_t h;
		if (nvs_open(kNvsNamespace, NVS_READWRITE, &h) != ESP_OK)
		{
			return false;
		}
		bool ok = (nvs_set_str(h, kKeyApPsk, psk.c_str()) == ESP_OK) &&
		          (nvs_commit(h) == ESP_OK);
		nvs_close(h);
		return ok;
#else
		(void)psk;
		return true;
#endif
	}

	// Caller must hold state().mutex.
	// Returns the passphrase, generating + persisting one if none is stored, so
	// getApPsk() can never hand back something WPA2 would reject.
	std::string ensurePskLocked(ConfigState& s)
	{
		loadLocked(s);
		if (isValidPsk(s.apPsk))
		{
			return s.apPsk;
		}

		std::string fresh = generatePsk();
		s.apPsk = fresh;
		// A failed persist is NOT fatal: the AP still comes up this boot with the
		// in-memory passphrase. It would be worse to return an empty string and
		// have esp_wifi refuse the config.
		persistApPskLocked(fresh);
		return fresh;
	}

	// ---------------------------------------------------------------------
	// cfgseed helpers. Pure byte arithmetic, no struct overlay: casting a
	// packed-on-paper flash image to a C struct is undefined behaviour on
	// Cortex/Xtensa (alignment + padding are the compiler's business, not the
	// wire format's) and would silently misread the moment padding changed.
	// ---------------------------------------------------------------------
	[[maybe_unused]] uint16_t readLe16(const uint8_t* p)
	{
		return static_cast<uint16_t>(p[0]) |
		       static_cast<uint16_t>(static_cast<uint16_t>(p[1]) << 8);
	}

	[[maybe_unused]] uint32_t readLe32(const uint8_t* p)
	{
		return static_cast<uint32_t>(p[0]) |
		       (static_cast<uint32_t>(p[1]) << 8) |
		       (static_cast<uint32_t>(p[2]) << 16) |
		       (static_cast<uint32_t>(p[3]) << 24);
	}

	// A fixed-width, NUL-padded seed string field as a std::string.
	// Defensive on both counts the wire format allows: the field may be exactly
	// full (no terminator), and it may be erased flash (0xFF everywhere). We stop
	// at the first NUL and never read past `width`.
	[[maybe_unused]] std::string readSeedString(const uint8_t* base, size_t off, size_t width)
	{
		size_t n = 0;
		while (n < width && base[off + n] != '\0')
		{
			++n;
		}
		return std::string(reinterpret_cast<const char*>(base + off), n);
	}

	// ---------------------------------------------------------------------
	// Schema versioning (issue #181). See DeviceConfig.hpp for the decision
	// table and the downgrade argument.
	// ---------------------------------------------------------------------

	// Set once at boot by ensureSchemaVersion(), read afterwards from whatever
	// task asks. Atomics rather than the ConfigState mutex: this pair is written
	// before any task exists and read forever after, so a lock would only buy
	// contention, and taking state().mutex here would tie schema detection to
	// the AP-passphrase state it has nothing to do with.
	std::atomic<DeviceConfig::SchemaOutcome> g_schemaOutcome{
		DeviceConfig::SchemaOutcome::StoreUnavailable};
	std::atomic<uint16_t> g_schemaObserved{0};

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	constexpr const char* kSchemaLogTag = "cfgschema";

	// Every NVS namespace whose contents are operator configuration. If ANY of
	// them exists on flash, the device has been provisioned and an absent stamp
	// means "pre-versioning", not "brand new".
	//
	// Deliberately excluded: "cdrlog" (CdrRing). Call records are history, not
	// configuration — a board that has only ever logged calls is still a blank
	// device as far as the key LAYOUT is concerned, and including it would make
	// the adoption path depend on whether anyone happened to dial.
	constexpr const char* kConfigNamespaces[] = {
		"storage",   // this file, AdminAuth, the transports
		"pbxcfg",    // dial plan, ring groups, page zones, reg_mode, syslog
		"sipauth",   // SipSecretStore
		"didmap",    // DidMapping
		"tapicfg",   // TelephonyApiConfig (trunk slots + secrets)
	};

	// Does `ns` exist on flash? nvs_open() in READONLY mode is the only probe
	// that does not answer its own question: READWRITE would CREATE the
	// namespace and make every device look provisioned.
	//
	//   1 = present, 0 = definitively absent, -1 = could not tell.
	// The -1 case must not collapse into 0: a store we cannot read is not a
	// blank store, and stamping a provisioned device as fresh is precisely the
	// failure this whole mechanism exists to prevent.
	int probeNamespace(const char* ns)
	{
		nvs_handle_t h;
		esp_err_t err = nvs_open(ns, NVS_READONLY, &h);
		if (err == ESP_OK)
		{
			nvs_close(h);
			return 1;
		}
		if (err == ESP_ERR_NVS_NOT_FOUND)
		{
			return 0;
		}
		return -1;
	}

	// Write the stamp. Every return checked; a failed commit is reported so the
	// caller can downgrade the outcome rather than claim a migration landed.
	bool writeSchemaVersion(uint16_t version)
	{
		nvs_handle_t h;
		if (nvs_open(kNvsNamespace, NVS_READWRITE, &h) != ESP_OK)
		{
			return false;
		}
		bool ok = (nvs_set_u16(h, DeviceConfig::kKeySchemaVersion, version) == ESP_OK) &&
		          (nvs_commit(h) == ESP_OK);
		nvs_close(h);
		return ok;
	}

	// Adapter matching DeviceConfig::SchemaStampFn, so the pure walker in
	// runSchemaMigrations() can commit each step without knowing about NVS.
	bool stampAfterStep(void* /*ctx*/, uint16_t version)
	{
		return writeSchemaVersion(version);
	}
#endif
}

namespace DeviceConfig
{
	bool isApSecure()
	{
		ConfigState& s = state();
		std::lock_guard<std::mutex> lock(s.mutex);
		loadLocked(s);
		return s.apSecure;
	}

	bool setApSecure(bool secure)
	{
		ConfigState& s = state();
		std::lock_guard<std::mutex> lock(s.mutex);
		loadLocked(s);

		// Turning WPA2 ON must never leave the caller with a secure AP and no
		// passphrase to hand out, so materialise one first.
		if (secure)
		{
			ensurePskLocked(s);
		}

		bool prev = s.apSecure;
		s.apSecure = secure;
		if (!persistApSecureLocked(secure))
		{
			// Roll back the in-memory state if persistence failed, so a later
			// bringup and the dashboard agree on what is actually stored.
			s.apSecure = prev;
			return false;
		}
		return true;
	}

	std::string getApPsk()
	{
		ConfigState& s = state();
		std::lock_guard<std::mutex> lock(s.mutex);
		return ensurePskLocked(s);
	}

	std::string regenerateApPsk()
	{
		ConfigState& s = state();
		std::lock_guard<std::mutex> lock(s.mutex);
		loadLocked(s);

		std::string fresh = generatePsk();
		s.apPsk = fresh;
		persistApPskLocked(fresh);
		return fresh;
	}

	bool setApPsk(const std::string& psk)
	{
		if (!isValidPsk(psk))
		{
			return false;
		}

		ConfigState& s = state();
		std::lock_guard<std::mutex> lock(s.mutex);
		loadLocked(s);

		std::string prev = s.apPsk;
		s.apPsk = psk;
		if (!persistApPskLocked(psk))
		{
			s.apPsk = prev;
			return false;
		}
		return true;
	}

}

namespace
{
	// ---------------------------------------------------------------------
	// WiFi station config readback (issue #186). Host-only mirror: on ESP
	// these functions never cache anything (see the .hpp comment on why), so
	// there is nothing here for the ESP branch to use. Kept separate from
	// ConfigState deliberately — its `loaded`-once cache is the wrong shape
	// for a value other writers can change out from under it.
	// ---------------------------------------------------------------------
	std::mutex& wifiMirrorMutex()
	{
		static std::mutex m;
		return m;
	}
	struct WifiStationMirror
	{
		std::string ssid;
		std::string password;
		uint8_t     mode = 0;
	};
	WifiStationMirror& wifiMirror()
	{
		static WifiStationMirror w;
		return w;
	}
}

namespace DeviceConfig
{
	std::string getWifiSsid()
	{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
		std::string result;
		nvs_handle_t h;
		if (nvs_open(kNvsNamespace, NVS_READONLY, &h) == ESP_OK)
		{
			char buf[64] = {0};
			size_t len = sizeof(buf);
			if (nvs_get_str(h, "wifi_ssid", buf, &len) == ESP_OK)
			{
				result = buf;
			}
			nvs_close(h);
		}
		return result;
#else
		std::lock_guard<std::mutex> lock(wifiMirrorMutex());
		return wifiMirror().ssid;
#endif
	}

	uint8_t getWifiMode()
	{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
		uint8_t mode = 0;
		nvs_handle_t h;
		if (nvs_open(kNvsNamespace, NVS_READONLY, &h) == ESP_OK)
		{
			// Explicit check (CONTRIBUTING_FIRMWARE.md Pattern 4): an absent
			// key or any other read failure must leave `mode` at its safe
			// pre-initialized default (0, captive-portal) rather than an
			// unchecked call merely happening to leave it there today.
			if (nvs_get_u8(h, "wifi_mode", &mode) != ESP_OK)
			{
				mode = 0;
			}
			nvs_close(h);
		}
		return mode;
#else
		std::lock_guard<std::mutex> lock(wifiMirrorMutex());
		return wifiMirror().mode;
#endif
	}

	std::string getWifiPassword()
	{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
		std::string result;
		nvs_handle_t h;
		if (nvs_open(kNvsNamespace, NVS_READONLY, &h) == ESP_OK)
		{
			char buf[128] = {0};
			size_t len = sizeof(buf);
			if (nvs_get_str(h, "wifi_pass", buf, &len) == ESP_OK)
			{
				result = buf;
			}
			nvs_close(h);
		}
		return result;
#else
		std::lock_guard<std::mutex> lock(wifiMirrorMutex());
		return wifiMirror().password;
#endif
	}

	bool setWifiConfig(const std::string& ssid, uint8_t mode)
	{
		if (ssid.empty() || ssid.size() > 32 || mode > 2)
		{
			return false;
		}
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
		nvs_handle_t h;
		if (nvs_open(kNvsNamespace, NVS_READWRITE, &h) != ESP_OK)
		{
			return false;
		}
		bool ok = (nvs_set_str(h, "wifi_ssid", ssid.c_str()) == ESP_OK) &&
		          (nvs_set_u8(h, "wifi_mode", mode) == ESP_OK) &&
		          (nvs_commit(h) == ESP_OK);
		nvs_close(h);
		return ok;
#else
		std::lock_guard<std::mutex> lock(wifiMirrorMutex());
		wifiMirror().ssid = ssid;
		wifiMirror().mode = mode;
		return true;
#endif
	}

	bool setWifiPassword(const std::string& password)
	{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
		nvs_handle_t h;
		if (nvs_open(kNvsNamespace, NVS_READWRITE, &h) != ESP_OK)
		{
			return false;
		}
		bool ok = (nvs_set_str(h, "wifi_pass", password.c_str()) == ESP_OK) &&
		          (nvs_commit(h) == ESP_OK);
		nvs_close(h);
		return ok;
#else
		std::lock_guard<std::mutex> lock(wifiMirrorMutex());
		wifiMirror().password = password;
		return true;
#endif
	}
}

namespace DeviceConfig
{
	bool applyFlashSeed()
	{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
		// Subtype 0x41 matches the `cfgseed` row in partitions.csv. A NULL result
		// is the NORMAL case, not an error: an OTA update does not rewrite the
		// partition table, so this firmware runs on boards flashed before cfgseed
		// existed, and the 4 MB sdkconfig.defaults.esp32_constrained layout has no
		// room for it either. Return quietly — no log, no error.
		const esp_partition_t* part = esp_partition_find_first(
			ESP_PARTITION_TYPE_DATA, (esp_partition_subtype_t)0x41, "cfgseed");
		if (part == nullptr)
		{
			return false;
		}
		if (part->size < kSeedSize)
		{
			return false;
		}

		uint8_t buf[kSeedSize] = {0};
		if (esp_partition_read(part, 0, buf, sizeof(buf)) != ESP_OK)
		{
			return false;
		}
		// NOTE: nothing below ever writes to `part`. The erase-before-write
		// discipline partitions.csv documents for raw partitions does not apply
		// to us precisely because the firmware only ever reads this one.

		if (readLe32(buf + 0) != kSeedMagic)
		{
			return false;   // erased flash (0xFFFFFFFF) lands here
		}
		if (readLe16(buf + 4) != kSeedVersion)
		{
			return false;   // a future flasher's format — ignore, don't guess
		}
		if (readLe32(buf + 252) != crc32Ieee(buf, 252))
		{
			return false;   // torn or corrupt write
		}

		const uint16_t flags    = readLe16(buf + 6);
		const uint32_t gen      = readLe32(buf + 8);
		const uint8_t  wifiMode = buf[12];
		const uint8_t  regMode  = buf[13];

		ConfigState& s = state();
		std::lock_guard<std::mutex> lock(s.mutex);
		loadLocked(s);

		nvs_handle_t h;
		if (nvs_open(kNvsNamespace, NVS_READWRITE, &h) != ESP_OK)
		{
			return false;
		}

		// Generation gate. A seed is applied ONCE: without this, every reboot
		// would re-clobber settings the operator changed from the dashboard since
		// flashing. A missing key means "never applied", so a freshly-erased NVS
		// re-applies the seed — which is exactly what /api/factory-reset wants.
		uint32_t storedGen = 0;
		bool haveStoredGen = (nvs_get_u32(h, kKeySeedGen, &storedGen) == ESP_OK);
		if (haveStoredGen && storedGen == gen)
		{
			nvs_close(h);
			return false;
		}

		bool applied = false;

		if (flags & kSeedHasApSecure)
		{
			uint8_t secure = (flags & kSeedApSecureOn) ? 1 : 0;
			if (nvs_set_u8(h, kKeyApSecure, secure) == ESP_OK)
			{
				s.apSecure = (secure != 0);
				applied = true;
			}
		}

		if (flags & kSeedHasApPsk)
		{
			std::string psk = readSeedString(buf, 16, 64);
			// An out-of-bounds or non-printable passphrase is DROPPED rather than
			// stored: writing it would hand esp_wifi a config it rejects, and the
			// AP would fail to start at all. Leaving the previous (or generated)
			// passphrase in place keeps the device reachable.
			if (isValidPsk(psk) && nvs_set_str(h, kKeyApPsk, psk.c_str()) == ESP_OK)
			{
				s.apPsk = psk;
				applied = true;
			}
		}

		if (flags & kSeedHasWifiMode)
		{
			// Only the three values the transports understand; anything else would
			// send esp_main_display.cpp's boot-priority ladder down an undefined
			// branch. Note this key is honoured on the pure-Ethernet builds too,
			// which is why applyFlashSeed() runs there as well.
			if (wifiMode <= 2 && nvs_set_u8(h, "wifi_mode", wifiMode) == ESP_OK)
			{
				applied = true;
			}
		}

		if (flags & kSeedHasRegMode)
		{
			// The SIP registrar's admission mode. Written as a RAW u8 to the key
			// Registrar::loadMode() reads: "reg_mode" in the **"pbxcfg"**
			// namespace (pbxpersist::kNvsNamespace, src/SIP/PbxPersist.hpp) — NOT
			// this function's own "storage" namespace, which is why it needs its
			// own handle below.
			//
			// The literal is duplicated here deliberately, WITHOUT including any
			// src/SIP header: this translation unit is also compiled into the host
			// test suite and into the pure-Ethernet transports, and pulling the
			// registrar in would drag its dependencies along for no gain.
			// DeviceConfig_test.cpp static_asserts the two against each other so
			// they cannot drift apart again.
			//
			// This was issue #151: the write went to `h` ("storage") while
			// loadMode() read "pbxcfg", so the flash-time registrar mode silently
			// did nothing on every release that shipped it. It stayed invisible
			// because a second bug (the byte-swapped partition magic fixed in
			// e559368) meant no seed was ever written at all, so this line never
			// got the chance to fail until v1.4.0.
			//
			// The values mirror Registrar::Mode byte for byte: 0 = open,
			// 1 = learn, 2 = secure. That duplication is only safe because of the
			// range check below — if the enum ever grew or was reordered, a seed
			// carrying the new value would be dropped here rather than silently
			// installing an admission mode this firmware does not understand, and
			// Registrar::loadMode() applies the same clamp on the way back out.
			//
			// WHY THIS PATH EXISTS AT ALL: RequestsHandler::setRegistrarMode() is
			// only ever called from the tests. Nothing on the device — no HTTP
			// endpoint, no on-glass control — writes `reg_mode`, so a shipped board
			// comes up in the compiled-in default and stays there forever, and the
			// fully-implemented SIP digest auth is unreachable in practice. The
			// flash-time seed is therefore the one way an operator can hand a
			// HEADLESS board (esp32s3-wifi / esp32s3-eth, no screen, and no
			// dashboard access until it is on a network) a `secure` or `learn`
			// registrar. A dashboard endpoint covers the boards that do have one.
			if (regMode <= 2)
			{
				// Separate handle on a different namespace from every other field
				// this function writes, committed and closed inside the helper
				// rather than deferred to the shared commit below, which only
				// covers `h`. See writeRegistrarMode (issues #151 / #188).
				if (writeRegistrarMode(regMode))
				{
					applied = true;
				}
			}
		}

		if (flags & kSeedHasStaCreds)
		{
			std::string ssid = readSeedString(buf, 80, 33);
			std::string pass = readSeedString(buf, 116, 64);
			// SSID: 1..32 octets (IEEE 802.11). The passphrase has NO lower bound
			// here — an upstream open network legitimately has an empty one — but
			// it must fit WPA2's 63-char maximum and stay printable.
			bool ssidOk = (!ssid.empty() && ssid.size() <= 32);
			bool passOk = (pass.size() <= kMaxPskChars);
			for (char c : pass)
			{
				unsigned char u = static_cast<unsigned char>(c);
				if (u < 0x20 || u > 0x7E)
				{
					passOk = false;
				}
			}
			// Written as a PAIR: an SSID with the wrong neighbour's password is a
			// device that never associates, so a bad half discards both.
			if (ssidOk && passOk &&
			    nvs_set_str(h, "wifi_ssid", ssid.c_str()) == ESP_OK &&
			    nvs_set_str(h, "wifi_pass", pass.c_str()) == ESP_OK)
			{
				applied = true;
			}
		}

		// Record the generation even when every flagged field was rejected, so a
		// seed we have decided we cannot use is not re-parsed on every boot.
		nvs_set_u32(h, kKeySeedGen, gen);
		nvs_commit(h);
		nvs_close(h);

		return applied;
#else
		// Host: no partition table to read. Returning false (rather than
		// simulating a seed) keeps the host suite exercising the same "no seed
		// present" branch a normally-flashed device takes.
		return false;
#endif
	}

	void clearAll()
	{
		ConfigState& s = state();
		std::lock_guard<std::mutex> lock(s.mutex);

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
		nvs_handle_t h;
		if (nvs_open(kNvsNamespace, NVS_READWRITE, &h) == ESP_OK)
		{
			nvs_erase_key(h, kKeyApSecure);
			nvs_erase_key(h, kKeyApPsk);
			// Dropping cfgseed_gen is deliberate — see DeviceConfig.hpp: the next
			// boot re-applies the flash-time seed, so "factory" means "as flashed".
			nvs_erase_key(h, kKeySeedGen);
			nvs_commit(h);
			nvs_close(h);
		}

		// The registrar admission mode goes too. This key belongs to Registrar,
		// but DeviceConfig is what writes it from the flash seed, and leaving it
		// behind makes factory reset unable to rescue the one state that most
		// needs rescuing: a device switched to `secure` before any extension was
		// secured rejects every REGISTER, locking every phone (and thus the
		// operator) out. Without this the only way back is USB.
		//
		// #188: this erase used to run against the `storage` handle above, which
		// is the wrong namespace — Registrar keeps reg_mode in `pbxcfg` — so the
		// rescue never actually worked. It is OUTSIDE the block above because it
		// is a different namespace and must happen whether or not `storage`
		// opened; eraseRegistrarMode() owns that choice now.
		eraseRegistrarMode();
#endif

		s.apSecure = false;
		s.apPsk.clear();
		s.loaded = true;    // we know the (now empty) state; don't reload

		// NOTE: `schema_ver` is NOT erased here, and that is deliberate.
		// clearAll() drops three keys out of "storage"; it does not touch
		// "pbxcfg", "sipauth", "didmap" or "tapicfg", so the device still holds
		// config in the CURRENT layout after a factory reset. Erasing the stamp
		// would make the next boot see "data, no stamp", conclude v1, and on a
		// future v3 firmware re-run the 1->2->3 migrations over data that is
		// already v3. The stamp describes the layout, not the contents, and a
		// factory reset does not change the layout.
	}

	// =====================================================================
	// Schema versioning (issue #181)
	// =====================================================================

	const char* schemaOutcomeName(SchemaOutcome outcome)
	{
		switch (outcome)
		{
			case SchemaOutcome::FreshInstall:     return "fresh-install";
			case SchemaOutcome::AdoptedLegacy:    return "adopted-legacy";
			case SchemaOutcome::UpToDate:         return "up-to-date";
			case SchemaOutcome::Migrated:         return "migrated";
			case SchemaOutcome::MigrationFailed:  return "migration-failed";
			case SchemaOutcome::Downgrade:        return "downgrade";
			case SchemaOutcome::StoreUnavailable: return "store-unavailable";
		}
		return "unknown";
	}

	SchemaPlan planSchema(const SchemaProbe& probe, uint16_t current)
	{
		SchemaPlan plan;

		// Could not inspect the store at all. Every field stays at its "do
		// nothing" default: no stamp, no migration, versions left at 0. This is
		// the one branch that must never fall through to FreshInstall.
		if (!probe.storeReadable)
		{
			plan.outcome = SchemaOutcome::StoreUnavailable;
			return plan;
		}

		// A stored zero is treated as NO stamp rather than as version 0. No
		// release has ever written 0, so reading one means a foreign or corrupt
		// write; routing it through the legacy path re-stamps it correctly
		// instead of leaving a meaningless value on flash forever.
		const bool haveVersion = probe.versionPresent && probe.version != 0;

		plan.toVersion = current;
		if (haveVersion)
		{
			plan.fromVersion = probe.version;
		}
		else if (probe.hasExistingData)
		{
			// THE line this whole feature exists for. A provisioned device with
			// no stamp is a pre-versioning device, and every release that could
			// have written its data wrote the v1 layout. Assume v1 and migrate
			// forward. Do not wipe, and do not assume `current` — assuming
			// current would skip the migrations a legacy device actually needs.
			plan.fromVersion = kSchemaBaselineVersion;
		}
		else
		{
			// Genuinely blank: nothing to migrate, born at today's layout.
			plan.fromVersion = current;
		}

		// The label reports the primary FACT about the device, which is not
		// always the same as the action. A legacy device on a v3 firmware is
		// reported as adopted-legacy (with fromVersion 1) even though it also
		// migrates — "we adopted an unstamped device" is the thing an operator
		// reading a boot log needs to see.
		if (!haveVersion)
		{
			plan.outcome = probe.hasExistingData ? SchemaOutcome::AdoptedLegacy
			                                     : SchemaOutcome::FreshInstall;
		}
		else if (plan.fromVersion > current)
		{
			plan.outcome = SchemaOutcome::Downgrade;
		}
		else if (plan.fromVersion < current)
		{
			plan.outcome = SchemaOutcome::Migrated;
		}
		else
		{
			plan.outcome = SchemaOutcome::UpToDate;
		}

		// A downgrade writes nothing at all: stamping backwards would let the
		// newer firmware come back and mistake its own v2 data for v1.
		// UpToDate writes nothing either, so a plain reboot costs no flash wear.
		plan.migrate = (plan.outcome != SchemaOutcome::Downgrade) &&
		               (plan.fromVersion < current);
		plan.stamp   = (plan.outcome != SchemaOutcome::Downgrade) &&
		               (plan.outcome != SchemaOutcome::UpToDate);
		return plan;
	}

	const SchemaMigration* schemaMigrations(size_t* count)
	{
		// Empty on purpose. kSchemaVersion is 1: there is no earlier layout to
		// come from, so any row here would be a speculative, untested,
		// flash-mutating code path shipped to production. The dispatch in
		// runSchemaMigrations() is fully exercised by the host tests against
		// synthetic tables instead, so adding the first real row is a two-line
		// change to this function and nothing else.
		if (count != nullptr)
		{
			*count = 0;
		}
		return nullptr;
	}

	bool runSchemaMigrations(uint16_t from, uint16_t to,
	                         const SchemaMigration* table, size_t count,
	                         void* ctx, SchemaStampFn stamp, uint16_t* reached)
	{
		if (reached == nullptr || stamp == nullptr)
		{
			return false;
		}
		*reached = from;
		if (from >= to)
		{
			return true;   // nothing to do is success
		}

		uint16_t at = from;
		// Bounded by `count`, not just by `at < to`: a table containing a cycle
		// (2->1 alongside 1->2) would otherwise spin forever at boot. No row is
		// usable more than once in a strictly increasing walk, so `count` steps
		// is a hard upper bound on a well-formed chain.
		for (size_t guard = 0; at < to && guard <= count; ++guard)
		{
			const SchemaMigration* step = nullptr;
			for (size_t i = 0; i < count && table != nullptr; ++i)
			{
				if (table[i].from == at)
				{
					step = &table[i];
					break;
				}
			}
			// A gap is a hard failure, never a skip. Jumping from v1 straight to
			// v3 because nobody wrote the 1->2 row would stamp a device as
			// finished over data that was never converted.
			if (step == nullptr || step->fn == nullptr || step->to <= at)
			{
				return false;
			}

			if (!step->fn(ctx))
			{
				return false;
			}
			// Commit the new version BEFORE attempting the next step, so an
			// interrupted chain resumes at the last layout that actually landed
			// rather than re-running conversions that already ran.
			if (!stamp(ctx, step->to))
			{
				return false;
			}
			at = step->to;
			*reached = at;
		}
		return at >= to;
	}

	SchemaOutcome lastSchemaOutcome()
	{
		return g_schemaOutcome.load(std::memory_order_acquire);
	}

	uint16_t observedSchemaVersion()
	{
		return g_schemaObserved.load(std::memory_order_acquire);
	}

	SchemaOutcome ensureSchemaVersion()
	{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
		SchemaProbe probe;

		// ---- Probe, READONLY throughout ----
		// Order matters: the stamp namespace is read first and NEVER opened
		// READWRITE before the decision is taken, because opening it READWRITE
		// creates it and would make hasExistingData unconditionally true.
		nvs_handle_t ro;
		esp_err_t err = nvs_open(kNvsNamespace, NVS_READONLY, &ro);
		if (err == ESP_OK)
		{
			probe.storeReadable = true;
			// The namespace existing at all means something wrote it, which on a
			// pre-versioning image means ap_psk / the admin PIN / wifi creds.
			probe.hasExistingData = true;

			uint16_t stored = 0;
			esp_err_t gerr = nvs_get_u16(ro, kKeySchemaVersion, &stored);
			nvs_close(ro);

			if (gerr == ESP_OK)
			{
				probe.versionPresent = true;
				probe.version = stored;
			}
			else if (gerr != ESP_ERR_NVS_NOT_FOUND)
			{
				// Anything else (INVALID_LENGTH from a key stored at the wrong
				// type, an IO error) means we do not know what is on flash.
				// Refuse to guess rather than adopt or stamp.
				probe.storeReadable = false;
			}
		}
		else if (err == ESP_ERR_NVS_NOT_FOUND)
		{
			// Definitively absent is an ANSWER, not a failure.
			probe.storeReadable = true;
		}

		// Only reached when "storage" itself was absent; if it existed we already
		// know the device is provisioned and the answer cannot change. The list
		// still contains "storage" (it re-probes as absent, one wasted nvs_open)
		// so that kConfigNamespaces stays the single complete statement of which
		// namespaces count as config — a reader adding a sixth one should not
		// have to notice that the first is handled somewhere else.
		if (probe.storeReadable && !probe.hasExistingData)
		{
			for (const char* ns : kConfigNamespaces)
			{
				int present = probeNamespace(ns);
				if (present < 0)
				{
					probe.storeReadable = false;
					break;
				}
				if (present > 0)
				{
					probe.hasExistingData = true;
					break;
				}
			}
		}

		// ---- Decide ----
		const SchemaPlan plan = planSchema(probe, kSchemaVersion);
		g_schemaObserved.store(plan.fromVersion, std::memory_order_release);

		SchemaOutcome outcome = plan.outcome;

		// ---- Act ----
		uint16_t reached = plan.fromVersion;
		if (plan.migrate)
		{
			size_t count = 0;
			const SchemaMigration* table = schemaMigrations(&count);
			if (!runSchemaMigrations(plan.fromVersion, plan.toVersion,
			                         table, count, nullptr, &stampAfterStep,
			                         &reached))
			{
				outcome = SchemaOutcome::MigrationFailed;
			}
		}

		// runSchemaMigrations() has already stamped every step it completed, so
		// the only stamp left to write is the one for a device that needed no
		// migration at all (fresh install, or a legacy adoption on a firmware
		// whose version equals the baseline).
		if (plan.stamp && reached == plan.fromVersion &&
		    !(probe.versionPresent && probe.version == reached))
		{
			if (!writeSchemaVersion(reached))
			{
				// The device is perfectly usable; it will simply be re-adopted
				// (identically) on the next boot. Worth a warning, not a fault.
				ESP_LOGW(kSchemaLogTag,
				         "could not persist schema stamp v%u; will re-detect next boot",
				         (unsigned)reached);
			}
		}

		// ---- Report ----
		if (outcome == SchemaOutcome::Downgrade)
		{
			// The loud one. See DeviceConfig.hpp: we boot anyway, because OTA
			// rollback lands here automatically and a PBX that refuses to ring
			// is worse than one running on possibly-misread config.
			ESP_LOGE(kSchemaLogTag,
			         "*** NVS SCHEMA DOWNGRADE: flash holds v%u, this firmware understands v%u ***",
			         (unsigned)plan.fromVersion, (unsigned)kSchemaVersion);
			ESP_LOGE(kSchemaLogTag,
			         "*** configuration may be MISREAD. Re-flash the newer firmware, or "
			         "factory-reset to re-provision. Nothing was written or migrated. ***");
		}
		else if (outcome == SchemaOutcome::MigrationFailed)
		{
			ESP_LOGE(kSchemaLogTag,
			         "schema migration stopped at v%u (target v%u); retrying next boot",
			         (unsigned)reached, (unsigned)kSchemaVersion);
		}
		else if (outcome == SchemaOutcome::StoreUnavailable)
		{
			ESP_LOGW(kSchemaLogTag,
			         "could not inspect NVS; schema left untouched and unstamped");
		}
		else if (outcome == SchemaOutcome::AdoptedLegacy)
		{
			ESP_LOGW(kSchemaLogTag,
			         "adopting pre-versioning config as schema v%u (now v%u); data preserved",
			         (unsigned)plan.fromVersion, (unsigned)reached);
		}
		else
		{
			ESP_LOGI(kSchemaLogTag, "schema %s (v%u)",
			         schemaOutcomeName(outcome), (unsigned)reached);
		}

		g_schemaOutcome.store(outcome, std::memory_order_release);
		return outcome;
#else
		// Host: no NVS. The in-memory store is rebuilt from nothing every
		// process, so it is blank by definition — the same reasoning that makes
		// applyFlashSeed() a no-op here. Reporting FreshInstall keeps the host
		// suite on the branch a normally-flashed device takes.
		g_schemaObserved.store(kSchemaVersion, std::memory_order_release);
		g_schemaOutcome.store(SchemaOutcome::FreshInstall, std::memory_order_release);
		return SchemaOutcome::FreshInstall;
#endif
	}
}
