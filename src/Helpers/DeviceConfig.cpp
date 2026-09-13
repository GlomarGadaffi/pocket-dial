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
				// Separate handle: a different namespace from every other field
				// this function writes. Committed and closed here rather than
				// deferred to the shared commit below, which only covers `h`.
				nvs_handle_t rh;
				if (nvs_open(kRegistrarNvsNamespace, NVS_READWRITE, &rh) == ESP_OK)
				{
					if (nvs_set_u8(rh, "reg_mode", regMode) == ESP_OK)
					{
						nvs_commit(rh);
						applied = true;
					}
					nvs_close(rh);
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
			// The registrar admission mode goes too. This key belongs to
			// Registrar, but DeviceConfig is what writes it from the flash seed,
			// and leaving it behind made factory reset unable to rescue the one
			// state that most needs rescuing: a device switched to `secure`
			// before any extension was secured rejects every REGISTER, locking
			// every phone (and thus the operator) out. Without this, the only
			// way back was USB.
			nvs_erase_key(h, kKeyRegMode);
			nvs_commit(h);
			nvs_close(h);
		}
#endif

		s.apSecure = false;
		s.apPsk.clear();
		s.loaded = true;    // we know the (now empty) state; don't reload
	}
}
