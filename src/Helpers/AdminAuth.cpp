// AdminAuth.cpp: platform-portable admin credential + session manager.
//
// See AdminAuth.hpp for the design rationale. This file is intentionally
// dependency-free beyond the C++17 standard library and the platform guards.
//
// Crypto: a small, self-contained SHA-256 (public-domain reference
// implementation of FIPS 180-4) is used on BOTH host and ESP so that the
// stored credential is identical and portable, and so the host build needs no
// external crypto library. Secrets (the login password and the DTMF PIN) are
// stored as salt + iterated SHA-256 (a PBKDF-style key-stretch) — never in
// cleartext. The username is stored in cleartext (it is an identity, not a
// secret) alongside the password's salt/hash.
//
// Randomness: esp_random() (a hardware CSPRNG) on ESP; on host, a
// std::random_device-seeded std::mt19937_64 (host is a developer/CI simulator,
// not the production trust boundary — documented in docs/THREAT_MODEL.md).

#include "AdminAuth.hpp"

#include <array>
#include <cctype>
#include <mutex>
#include <vector>
#include <cstring>
#include <chrono>

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	// On the device, credentials persist in NVS and randomness comes from the
	// hardware RNG. nvs_flash/nvs/esp_random are core ESP-IDF components present
	// on EVERY transport (wifi, eth, display) — they are not WiFi-specific, so
	// they must be gated on ESP_PLATFORM, not POCKETDIAL_HAS_WIFI.
	#include "nvs_flash.h"
	#include "nvs.h"
	#include "esp_random.h"
#else
	#include <random>
#endif

namespace
{
	// ---------------------------------------------------------------------
	// Self-contained SHA-256 (FIPS 180-4). Public-domain reference style.
	// Operates on bytes; produces a 32-byte digest.
	// ---------------------------------------------------------------------
	class Sha256
	{
	public:
		Sha256() { reset(); }

		void update(const uint8_t* data, size_t len)
		{
			for (size_t i = 0; i < len; ++i)
			{
				_buffer[_bufferLen++] = data[i];
				if (_bufferLen == 64)
				{
					transform(_buffer.data());
					_bitLen += 512;
					_bufferLen = 0;
				}
			}
		}

		void update(const std::string& s)
		{
			update(reinterpret_cast<const uint8_t*>(s.data()), s.size());
		}

		// Finalizes and writes the 32-byte digest into out.
		void finalize(uint8_t out[32])
		{
			uint64_t totalBits = _bitLen + static_cast<uint64_t>(_bufferLen) * 8;

			// Append the 0x80 padding byte.
			size_t i = _bufferLen;
			_buffer[i++] = 0x80;

			// If there is no room for the 8-byte length, pad+flush this block.
			if (i > 56)
			{
				while (i < 64) _buffer[i++] = 0x00;
				transform(_buffer.data());
				i = 0;
			}
			while (i < 56) _buffer[i++] = 0x00;

			// Append the message length as a big-endian 64-bit integer.
			for (int b = 7; b >= 0; --b)
			{
				_buffer[i++] = static_cast<uint8_t>((totalBits >> (b * 8)) & 0xFF);
			}
			transform(_buffer.data());

			// Emit the state in big-endian order.
			for (int j = 0; j < 8; ++j)
			{
				out[j * 4 + 0] = static_cast<uint8_t>((_state[j] >> 24) & 0xFF);
				out[j * 4 + 1] = static_cast<uint8_t>((_state[j] >> 16) & 0xFF);
				out[j * 4 + 2] = static_cast<uint8_t>((_state[j] >> 8) & 0xFF);
				out[j * 4 + 3] = static_cast<uint8_t>(_state[j] & 0xFF);
			}
		}

	private:
		void reset()
		{
			_state[0] = 0x6a09e667u;
			_state[1] = 0xbb67ae85u;
			_state[2] = 0x3c6ef372u;
			_state[3] = 0xa54ff53au;
			_state[4] = 0x510e527fu;
			_state[5] = 0x9b05688cu;
			_state[6] = 0x1f83d9abu;
			_state[7] = 0x5be0cd19u;
			_bufferLen = 0;
			_bitLen = 0;
		}

		static uint32_t rotr(uint32_t x, uint32_t n)
		{
			return (x >> n) | (x << (32 - n));
		}

		void transform(const uint8_t* chunk)
		{
			static const uint32_t k[64] = {
				0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
				0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
				0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
				0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
				0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
				0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
				0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
				0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
				0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
				0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
				0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
				0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
				0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
				0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
				0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
				0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
			};

			uint32_t w[64];
			for (int i = 0; i < 16; ++i)
			{
				w[i] = (static_cast<uint32_t>(chunk[i * 4 + 0]) << 24) |
				       (static_cast<uint32_t>(chunk[i * 4 + 1]) << 16) |
				       (static_cast<uint32_t>(chunk[i * 4 + 2]) << 8) |
				       (static_cast<uint32_t>(chunk[i * 4 + 3]));
			}
			for (int i = 16; i < 64; ++i)
			{
				uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
				uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
				w[i] = w[i - 16] + s0 + w[i - 7] + s1;
			}

			uint32_t a = _state[0];
			uint32_t b = _state[1];
			uint32_t c = _state[2];
			uint32_t d = _state[3];
			uint32_t e = _state[4];
			uint32_t f = _state[5];
			uint32_t g = _state[6];
			uint32_t h = _state[7];

			for (int i = 0; i < 64; ++i)
			{
				uint32_t s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
				uint32_t ch = (e & f) ^ ((~e) & g);
				uint32_t temp1 = h + s1 + ch + k[i] + w[i];
				uint32_t s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
				uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
				uint32_t temp2 = s0 + maj;

				h = g;
				g = f;
				f = e;
				e = d + temp1;
				d = c;
				c = b;
				b = a;
				a = temp1 + temp2;
			}

			_state[0] += a;
			_state[1] += b;
			_state[2] += c;
			_state[3] += d;
			_state[4] += e;
			_state[5] += f;
			_state[6] += g;
			_state[7] += h;
		}

		std::array<uint32_t, 8> _state{};
		std::array<uint8_t, 64> _buffer{};
		size_t   _bufferLen = 0;
		uint64_t _bitLen = 0;
	};

	std::string toHex(const uint8_t* data, size_t len)
	{
		static const char* digits = "0123456789abcdef";
		std::string out;
		out.reserve(len * 2);
		for (size_t i = 0; i < len; ++i)
		{
			out.push_back(digits[(data[i] >> 4) & 0x0F]);
			out.push_back(digits[data[i] & 0x0F]);
		}
		return out;
	}

	// Salted, iterated SHA-256 (PBKDF-style key-stretch). The iteration count
	// makes offline brute-forcing of a leaked hash markedly more expensive.
	// Returns a 64-char lowercase hex digest. Used for both the login password
	// and the DTMF PIN — same stretch cost either way.
	std::string hashSecret(const std::string& salt, const std::string& secret)
	{
		uint8_t digest[32];

		// Round 0: SHA-256(salt || secret).
		{
			Sha256 sha;
			sha.update(salt);
			sha.update(secret);
			sha.finalize(digest);
		}

		// Subsequent rounds: SHA-256(salt || previousDigest).
		for (uint32_t i = 1; i < AdminAuth::kHashIterations; ++i)
		{
			Sha256 sha;
			sha.update(salt);
			sha.update(digest, sizeof(digest));
			sha.finalize(digest);
		}

		return toHex(digest, sizeof(digest));
	}

	// Cryptographically-strong (on ESP) random bytes. On host, a PRNG seeded
	// from std::random_device — adequate for the host simulator.
	void fillRandom(uint8_t* buf, size_t len)
	{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
		// Hardware CSPRNG, available on every ESP transport.
		for (size_t i = 0; i < len; ++i)
		{
			buf[i] = static_cast<uint8_t>(esp_random() & 0xFF);
		}
#else
		// Host simulator: seed mt19937_64 from random_device once, also stirring
		// in a steady-clock sample. (Host is a developer/CI simulator, not the
		// production trust boundary — documented in docs/THREAT_MODEL.md.)
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

	std::string randomHex(size_t hexChars)
	{
		size_t nbytes = (hexChars + 1) / 2;
		std::vector<uint8_t> bytes(nbytes);
		fillRandom(bytes.data(), bytes.size());
		std::string hex = toHex(bytes.data(), bytes.size());
		hex.resize(hexChars);
		return hex;
	}

	// Constant-time string compare. Returns true iff equal. Designed not to
	// short-circuit on the first differing byte, so timing does not leak how
	// many leading characters matched. (Length is compared up front — for the
	// fixed-length hex digests this leaks nothing beyond "same length"; for the
	// username compare in verifyCredential() the password hash is always
	// computed regardless of this result, so a wrong username costs the same
	// wall-clock time as a wrong password.)
	bool constantTimeEquals(const std::string& a, const std::string& b)
	{
		if (a.size() != b.size())
		{
			return false;
		}
		unsigned char diff = 0;
		for (size_t i = 0; i < a.size(); ++i)
		{
			diff = static_cast<unsigned char>(
				diff | (static_cast<unsigned char>(a[i]) ^ static_cast<unsigned char>(b[i])));
		}
		return diff == 0;
	}

	bool usernameValid(const std::string& u)
	{
		if (u.size() < AdminAuth::kMinUsernameLength || u.size() > AdminAuth::kMaxUsernameLength)
		{
			return false;
		}
		for (char c : u)
		{
			// No whitespace or control characters — this is an identity string
			// rendered into JSON/NVS, not free text.
			if (std::iscntrl(static_cast<unsigned char>(c)) || std::isspace(static_cast<unsigned char>(c)))
			{
				return false;
			}
		}
		return true;
	}

	bool passwordValid(const std::string& p)
	{
		return p.size() >= AdminAuth::kMinPasswordLength && p.size() <= AdminAuth::kMaxPasswordLength;
	}

	bool dtmfPinValid(const std::string& p)
	{
		if (p.size() < AdminAuth::kMinDtmfPinLength || p.size() > AdminAuth::kMaxDtmfPinLength)
		{
			return false;
		}
		for (char c : p)
		{
			if (!std::isdigit(static_cast<unsigned char>(c)))
			{
				return false;
			}
		}
		return true;
	}

	uint64_t nowMs()
	{
		return static_cast<uint64_t>(
			std::chrono::duration_cast<std::chrono::milliseconds>(
				std::chrono::steady_clock::now().time_since_epoch()).count());
	}

	// ---------------------------------------------------------------------
	// Shared, mutex-guarded state.
	// ---------------------------------------------------------------------
	struct Session
	{
		std::string token;
		// Per-session CSRF token. Bound to the session by living in the same slot;
		// never sent as a cookie, so SameSite/HttpOnly protect the session id while
		// this protects against a same-site page that can still drive fetch().
		std::string csrf;
		uint64_t    expiresAtMs = 0;
		bool        used = false;
	};

	// One brute-force accounting bucket per client identity (see
	// AdminAuth::kMaxAttemptBuckets). `key` is the HTTP peer address; the empty
	// key is the unkeyed bucket used by callers with no peer (the DTMF menu).
	// Shared between login-credential and DTMF-PIN attempts.
	struct AttemptBucket
	{
		std::string key;
		bool        used = false;
		int         failures = 0;        // failures inside the current window
		int         trips = 0;           // lockouts engaged since the last success
		uint64_t    lockoutUntilMs = 0;
		uint64_t    lastSeenMs = 0;      // for least-recently-seen eviction
	};

	struct AuthState
	{
		std::mutex mutex;

		// In-memory mirror of the stored credentials. On ESP this is loaded from
		// NVS on first access; on host it IS the credential (host has no NVS).
		bool        loaded = false;     // have we tried to load from NVS yet?

		// Login credential (web dashboard). `provisioned` is true only once
		// setLoginCredential() has been called at least once — until then,
		// verifyCredential() accepts only the compiled-in default.
		bool        provisioned = false;
		std::string username;
		std::string pwSalt;             // hex
		std::string pwHash;             // hex (salted, iterated digest)

		// DTMF admin-menu PIN (phone keypad). No default — dtmfPinSet stays
		// false, and verifyDtmfPin() always fails, until setDtmfPin() is called.
		bool        dtmfPinSet = false;
		std::string pinSalt;            // hex
		std::string pinHash;            // hex (salted, iterated digest)

		// Brute-force lockout, tracked per client (docs/THREAT_MODEL.md §5.2, D-3).
		// Shared by login-credential and DTMF-PIN attempts.
		std::array<AttemptBucket, AdminAuth::kMaxAttemptBuckets> attempts{};

		// Aggregate backstop across every client, so that rotating source addresses
		// cannot buy an unbounded guess rate (see kMaxFailedAttemptsGlobal).
		int      globalFailures = 0;
		int      globalTrips = 0;
		uint64_t globalLockoutUntilMs = 0;

		std::array<Session, AdminAuth::kMaxSessions> sessions{};
	};

	// Function-local static: avoids a static-initialization-order fiasco and is
	// thread-safe to initialize under C++11+.
	AuthState& state()
	{
		static AuthState s;
		return s;
	}

	// --- NVS-backed persistence (ESP only); no-ops on host. ---
	// Caller must hold state().mutex.
	void loadCredentialLocked(AuthState& s)
	{
		if (s.loaded)
		{
			return;
		}
		s.loaded = true;

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
		nvs_handle_t h;
		if (nvs_open("storage", NVS_READWRITE, &h) == ESP_OK)
		{
			char userBuf[128] = {0};
			char saltBuf[128] = {0};
			char hashBuf[128] = {0};
			size_t userLen = sizeof(userBuf);
			size_t saltLen = sizeof(saltBuf);
			size_t hashLen = sizeof(hashBuf);
			esp_err_t e1 = nvs_get_str(h, "admin_user", userBuf, &userLen);
			esp_err_t e2 = nvs_get_str(h, "admin_pw_salt", saltBuf, &saltLen);
			esp_err_t e3 = nvs_get_str(h, "admin_pw_hash", hashBuf, &hashLen);
			if (e1 == ESP_OK && e2 == ESP_OK && e3 == ESP_OK &&
				userBuf[0] != '\0' && saltBuf[0] != '\0' && hashBuf[0] != '\0')
			{
				s.username = userBuf;
				s.pwSalt = saltBuf;
				s.pwHash = hashBuf;
				s.provisioned = true;
			}

			char pinSaltBuf[128] = {0};
			char pinHashBuf[128] = {0};
			size_t pinSaltLen = sizeof(pinSaltBuf);
			size_t pinHashLen = sizeof(pinHashBuf);
			esp_err_t e4 = nvs_get_str(h, "admin_pin_salt", pinSaltBuf, &pinSaltLen);
			esp_err_t e5 = nvs_get_str(h, "admin_pin_hash", pinHashBuf, &pinHashLen);
			if (e4 == ESP_OK && e5 == ESP_OK && pinSaltBuf[0] != '\0' && pinHashBuf[0] != '\0')
			{
				s.pinSalt = pinSaltBuf;
				s.pinHash = pinHashBuf;
				s.dtmfPinSet = true;
			}
			nvs_close(h);
		}
#else
		(void)s;
#endif
	}

	// Caller must hold state().mutex.
	bool persistLoginCredentialLocked(const AuthState& s)
	{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
		nvs_handle_t h;
		if (nvs_open("storage", NVS_READWRITE, &h) != ESP_OK)
		{
			return false;
		}
		bool ok = (nvs_set_str(h, "admin_user", s.username.c_str()) == ESP_OK) &&
		          (nvs_set_str(h, "admin_pw_salt", s.pwSalt.c_str()) == ESP_OK) &&
		          (nvs_set_str(h, "admin_pw_hash", s.pwHash.c_str()) == ESP_OK) &&
		          (nvs_commit(h) == ESP_OK);
		nvs_close(h);
		return ok;
#else
		// Host: the in-memory AuthState IS the store. Nothing else to do.
		(void)s;
		return true;
#endif
	}

	// Caller must hold state().mutex.
	bool persistDtmfPinLocked(const AuthState& s)
	{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
		nvs_handle_t h;
		if (nvs_open("storage", NVS_READWRITE, &h) != ESP_OK)
		{
			return false;
		}
		bool ok = (nvs_set_str(h, "admin_pin_salt", s.pinSalt.c_str()) == ESP_OK) &&
		          (nvs_set_str(h, "admin_pin_hash", s.pinHash.c_str()) == ESP_OK) &&
		          (nvs_commit(h) == ESP_OK);
		nvs_close(h);
		return ok;
#else
		(void)s;
		return true;
#endif
	}

	// --- Brute-force accounting buckets. Caller must hold state().mutex. ---

	// The bucket for `key`, or nullptr if this client has no history. Read-only:
	// used by isLockedOut(), which must not allocate a slot for a client that has
	// never guessed (otherwise merely asking would evict a real attacker's record).
	AttemptBucket* findBucketLocked(AuthState& s, const std::string& key)
	{
		for (auto& b : s.attempts)
		{
			if (b.used && b.key == key)
			{
				return &b;
			}
		}
		return nullptr;
	}

	// The bucket for `key`, creating one if needed. When the table is full the
	// least-recently-seen entry is reused; a client that keeps guessing keeps
	// touching its bucket, so the entry that gets dropped is always the most
	// stale one. This bounds memory against a flood of spoofed source addresses
	// at the cost of letting a large enough flood eventually recycle a record —
	// an accepted trade on a device whose AP holds ten stations.
	AttemptBucket& acquireBucketLocked(AuthState& s, const std::string& key)
	{
		if (AttemptBucket* existing = findBucketLocked(s, key))
		{
			existing->lastSeenMs = nowMs();
			return *existing;
		}

		AttemptBucket* victim = &s.attempts[0];
		for (auto& b : s.attempts)
		{
			if (!b.used)
			{
				victim = &b;
				break;
			}
			if (b.lastSeenMs < victim->lastSeenMs)
			{
				victim = &b;
			}
		}

		*victim = AttemptBucket{};
		victim->key = key;
		victim->used = true;
		victim->lastSeenMs = nowMs();
		return *victim;
	}

	// Shared lockout-and-accounting update used by both verifyCredential() and
	// verifyDtmfPin(). Caller must hold state().mutex and have already checked
	// the lockout gates before doing the (expensive) hash comparison; this only
	// updates the bookkeeping once the comparison result (`ok`) is known.
	void recordAttemptLocked(AuthState& s, AttemptBucket& b, bool ok)
	{
		if (ok)
		{
			b.failures = 0;
			b.trips = 0;
			b.lockoutUntilMs = 0;
			// A correct credential proves a legitimate operator is present, so it
			// clears the aggregate backstop too — otherwise a burst of noise from
			// the AP would keep punishing the admin after they had demonstrably
			// arrived.
			s.globalFailures = 0;
			s.globalTrips = 0;
			s.globalLockoutUntilMs = 0;
			return;
		}

		++b.failures;
		++s.globalFailures;
		if (s.globalFailures >= AdminAuth::kMaxFailedAttemptsGlobal)
		{
			++s.globalTrips;
			const int gshift = (s.globalTrips - 1 < AdminAuth::kMaxLockoutShift)
				? (s.globalTrips - 1) : AdminAuth::kMaxLockoutShift;
			s.globalLockoutUntilMs = nowMs() + (AdminAuth::kLockoutMs << gshift);
			s.globalFailures = 0;
		}
		if (b.failures >= AdminAuth::kMaxFailedAttempts)
		{
			// Escalating backoff: keep the trip count and double the cooldown each
			// time, rather than resetting it after every cooldown (which would
			// hand the attacker a fresh kMaxFailedAttempts window forever). Only a
			// correct credential clears it (above).
			++b.trips;
			const int shift = (b.trips - 1 < AdminAuth::kMaxLockoutShift)
				? (b.trips - 1) : AdminAuth::kMaxLockoutShift;
			b.lockoutUntilMs = nowMs() + (AdminAuth::kLockoutMs << shift);
			b.failures = 0;
		}
	}

	// Caller must hold state().mutex.
	void eraseCredentialLocked()
	{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
		nvs_handle_t h;
		if (nvs_open("storage", NVS_READWRITE, &h) == ESP_OK)
		{
			nvs_erase_key(h, "admin_user");
			nvs_erase_key(h, "admin_pw_salt");
			nvs_erase_key(h, "admin_pw_hash");
			nvs_erase_key(h, "admin_pin_salt");
			nvs_erase_key(h, "admin_pin_hash");
			nvs_commit(h);
			nvs_close(h);
		}
#endif
	}
}

namespace AdminAuth
{
	bool isProvisioned()
	{
		AuthState& s = state();
		std::lock_guard<std::mutex> lock(s.mutex);
		loadCredentialLocked(s);
		return s.provisioned;
	}

	bool needsInitialSetup()
	{
		return !isProvisioned();
	}

	bool setLoginCredential(const std::string& username, const std::string& password)
	{
		if (!usernameValid(username) || !passwordValid(password))
		{
			return false;
		}

		AuthState& s = state();
		std::lock_guard<std::mutex> lock(s.mutex);
		loadCredentialLocked(s);

		std::string salt = randomHex(32);   // 128-bit salt
		if (salt.empty())
		{
			return false;
		}
		std::string hash = hashSecret(salt, password);

		std::string prevUsername = s.username;
		std::string prevSalt = s.pwSalt;
		std::string prevHash = s.pwHash;
		bool        prevProvisioned = s.provisioned;

		s.username = username;
		s.pwSalt = salt;
		s.pwHash = hash;
		s.provisioned = true;

		if (!persistLoginCredentialLocked(s))
		{
			// Roll back the in-memory state if persistence failed.
			s.username = prevUsername;
			s.pwSalt = prevSalt;
			s.pwHash = prevHash;
			s.provisioned = prevProvisioned;
			return false;
		}

		// A credential (re)set clears brute-force accounting for every client
		// (shared table — also affects the DTMF PIN's accounting, which is
		// fine: whoever just authenticated to change the login credential has
		// already proven themselves).
		s.attempts = {};
		s.globalFailures = 0;
		s.globalTrips = 0;
		s.globalLockoutUntilMs = 0;
		return true;
	}

	bool isLockedOut()
	{
		return isLockedOut(std::string());
	}

	bool isLockedOut(const std::string& clientKey)
	{
		AuthState& s = state();
		std::lock_guard<std::mutex> lock(s.mutex);
		const uint64_t now = nowMs();
		if (s.globalLockoutUntilMs != 0 && now < s.globalLockoutUntilMs)
		{
			return true;   // aggregate backstop is engaged: everyone waits
		}
		AttemptBucket* b = findBucketLocked(s, clientKey);
		return b != nullptr && b->lockoutUntilMs != 0 && now < b->lockoutUntilMs;
	}

	bool verifyCredential(const std::string& username, const std::string& password,
		const std::string& clientKey)
	{
		AuthState& s = state();
		std::lock_guard<std::mutex> lock(s.mutex);
		loadCredentialLocked(s);

		AttemptBucket& b = acquireBucketLocked(s, clientKey);

		// Honor this client's lockout — and the aggregate backstop — without
		// hashing while either is engaged.
		if (b.lockoutUntilMs != 0 && nowMs() < b.lockoutUntilMs)
		{
			return false;
		}
		if (s.globalLockoutUntilMs != 0 && nowMs() < s.globalLockoutUntilMs)
		{
			return false;
		}

		bool ok;
		if (!s.provisioned)
		{
			// No real credential has ever been set: only the well-known default
			// verifies. Still subject to the same lockout accounting below — the
			// default is not a bypass of brute-force protection, and once
			// setLoginCredential() runs this branch never executes again.
			ok = (username == kDefaultUsername) && (password == kDefaultPassword);
		}
		else
		{
			// Compute the password hash unconditionally (even if the username is
			// already wrong) so a wrong username costs the same wall-clock time
			// as a wrong password — no timing signal on which one was correct.
			bool userOk = constantTimeEquals(username, s.username);
			std::string candidate = hashSecret(s.pwSalt, password);
			bool passOk = constantTimeEquals(candidate, s.pwHash);
			ok = userOk && passOk;
		}

		recordAttemptLocked(s, b, ok);
		return ok;
	}

	bool dtmfPinIsSet()
	{
		AuthState& s = state();
		std::lock_guard<std::mutex> lock(s.mutex);
		loadCredentialLocked(s);
		return s.dtmfPinSet;
	}

	bool setDtmfPin(const std::string& pin)
	{
		if (!dtmfPinValid(pin))
		{
			return false;
		}

		AuthState& s = state();
		std::lock_guard<std::mutex> lock(s.mutex);
		loadCredentialLocked(s);

		std::string salt = randomHex(32);
		if (salt.empty())
		{
			return false;
		}
		std::string hash = hashSecret(salt, pin);

		std::string prevSalt = s.pinSalt;
		std::string prevHash = s.pinHash;
		bool        prevSet = s.dtmfPinSet;

		s.pinSalt = salt;
		s.pinHash = hash;
		s.dtmfPinSet = true;

		if (!persistDtmfPinLocked(s))
		{
			s.pinSalt = prevSalt;
			s.pinHash = prevHash;
			s.dtmfPinSet = prevSet;
			return false;
		}

		s.attempts = {};
		s.globalFailures = 0;
		s.globalTrips = 0;
		s.globalLockoutUntilMs = 0;
		return true;
	}

	bool verifyDtmfPin(const std::string& pin)
	{
		AuthState& s = state();
		std::lock_guard<std::mutex> lock(s.mutex);
		loadCredentialLocked(s);

		if (!s.dtmfPinSet)
		{
			return false;
		}

		AttemptBucket& b = acquireBucketLocked(s, std::string());

		if (b.lockoutUntilMs != 0 && nowMs() < b.lockoutUntilMs)
		{
			return false;
		}
		if (s.globalLockoutUntilMs != 0 && nowMs() < s.globalLockoutUntilMs)
		{
			return false;
		}

		std::string candidate = hashSecret(s.pinSalt, pin);
		bool ok = constantTimeEquals(candidate, s.pinHash);

		recordAttemptLocked(s, b, ok);
		return ok;
	}

	std::string createSession()
	{
		AuthState& s = state();
		std::lock_guard<std::mutex> lock(s.mutex);

		std::string token = randomHex(kSessionTokenHex);
		if (token.empty())
		{
			return "";
		}

		uint64_t now = nowMs();

		// Find a free slot: prefer an unused one, else an expired one, else the
		// soonest-to-expire (evict the oldest).
		size_t slot = 0;
		bool found = false;
		uint64_t earliestExpiry = UINT64_MAX;
		for (size_t i = 0; i < s.sessions.size(); ++i)
		{
			Session& sess = s.sessions[i];
			if (!sess.used || (sess.expiresAtMs != 0 && now >= sess.expiresAtMs))
			{
				slot = i;
				found = true;
				break;
			}
			if (sess.expiresAtMs < earliestExpiry)
			{
				earliestExpiry = sess.expiresAtMs;
				slot = i;
			}
		}
		(void)found;

		s.sessions[slot].token = token;
		s.sessions[slot].csrf = randomHex(kCsrfTokenHex);
		s.sessions[slot].expiresAtMs = now + kSessionTtlMs;
		s.sessions[slot].used = true;
		return token;
	}

	bool validateSession(const std::string& token)
	{
		if (token.empty())
		{
			return false;
		}

		AuthState& s = state();
		std::lock_guard<std::mutex> lock(s.mutex);

		uint64_t now = nowMs();
		for (auto& sess : s.sessions)
		{
			if (!sess.used)
			{
				continue;
			}
			if (sess.expiresAtMs != 0 && now >= sess.expiresAtMs)
			{
				// Lazily reap expired sessions.
				sess.used = false;
				sess.token.clear();
				sess.csrf.clear();
				sess.expiresAtMs = 0;
				continue;
			}
			// Constant-time compare against each live token.
			if (constantTimeEquals(sess.token, token))
			{
				// Sliding expiry: an actively-used session is kept alive. Each
				// successful validation pushes the absolute deadline out by the
				// full TTL so a working admin isn't logged out mid-session.
				sess.expiresAtMs = now + AdminAuth::kSessionTtlMs;
				return true;
			}
		}
		return false;
	}

	void destroySession(const std::string& token)
	{
		if (token.empty())
		{
			return;
		}

		AuthState& s = state();
		std::lock_guard<std::mutex> lock(s.mutex);

		for (auto& sess : s.sessions)
		{
			if (sess.used && constantTimeEquals(sess.token, token))
			{
				sess.used = false;
				sess.token.clear();
				sess.csrf.clear();
				sess.expiresAtMs = 0;
			}
		}
	}

	void clearCredential()
	{
		AuthState& s = state();
		std::lock_guard<std::mutex> lock(s.mutex);

		eraseCredentialLocked();

		s.username.clear();
		s.pwSalt.clear();
		s.pwHash.clear();
		s.provisioned = false;
		s.pinSalt.clear();
		s.pinHash.clear();
		s.dtmfPinSet = false;
		s.loaded = true;          // we know the (now empty) state; don't reload
		s.attempts = {};
		s.globalFailures = 0;
		s.globalTrips = 0;
		s.globalLockoutUntilMs = 0;

		for (auto& sess : s.sessions)
		{
			sess.used = false;
			sess.token.clear();
			sess.csrf.clear();
			sess.expiresAtMs = 0;
		}
	}

	std::string sessionCsrf(const std::string& token)
	{
		if (token.empty())
		{
			return "";
		}

		AuthState& s = state();
		std::lock_guard<std::mutex> lock(s.mutex);

		uint64_t now = nowMs();
		for (auto& sess : s.sessions)
		{
			if (!sess.used)
			{
				continue;
			}
			if (sess.expiresAtMs != 0 && now >= sess.expiresAtMs)
			{
				continue;
			}
			if (constantTimeEquals(sess.token, token))
			{
				return sess.csrf;
			}
		}
		return "";
	}

	bool validateCsrf(const std::string& token, const std::string& csrf)
	{
		if (csrf.empty())
		{
			return false;
		}
		const std::string want = sessionCsrf(token);
		if (want.empty())
		{
			return false;
		}
		return constantTimeEquals(want, csrf);
	}

	uint64_t sessionRemainingMs(const std::string& token)
	{
		if (token.empty())
		{
			return 0;
		}

		AuthState& s = state();
		std::lock_guard<std::mutex> lock(s.mutex);

		const uint64_t now = nowMs();
		for (auto& sess : s.sessions)
		{
			if (!sess.used)
			{
				continue;
			}
			if (sess.expiresAtMs != 0 && now >= sess.expiresAtMs)
			{
				continue;
			}
			if (constantTimeEquals(sess.token, token))
			{
				return (sess.expiresAtMs == 0) ? 0 : (sess.expiresAtMs - now);
			}
		}
		return 0;
	}

	// credentialIsSet: lightweight NVS probe used by the boot provisioning gate.
	// Opens NVS namespace "storage", reads key "admin_pw_hash" as a string, and
	// returns true iff the string is non-empty. Closes the handle on exit.
	// On non-ESP builds it delegates to the in-memory isProvisioned() so the
	// host unit tests exercise the same logic path.
	bool credentialIsSet()
	{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
		nvs_handle_t h;
		if (nvs_open("storage", NVS_READONLY, &h) != ESP_OK)
		{
			return false;
		}
		char hashBuf[128] = {0};
		size_t hashLen = sizeof(hashBuf);
		esp_err_t err = nvs_get_str(h, "admin_pw_hash", hashBuf, &hashLen);
		nvs_close(h);
		return (err == ESP_OK && hashBuf[0] != '\0');
#else
		return isProvisioned();
#endif
	}
}
